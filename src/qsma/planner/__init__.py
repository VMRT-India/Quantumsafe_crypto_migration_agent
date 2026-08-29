"""
qsma.planner
============
LangGraph node: planner_node

Responsibilities
----------------
1. For every selected CryptoFinding (any language), call the LLM to produce
   a MigrationPlan — what algorithm to migrate to, what dependencies change,
   and transformation hints for the Migrator.

2. Determine dependency-safe execution order via topological sort of the
   finding dependency sub-graph.  High blast-radius findings (many things
   depend on them) must be migrated BEFORE their dependents, so that by the
   time a dependent module is migrated all of its crypto dependencies are
   already quantum-safe.

3. Pack the topo-sorted findings into parallel execution waves.  Findings
   in the same wave have no inter-dependencies and can be migrated
   simultaneously.  Max 6 findings per wave (parallel agent cap).

4. Emit a MigrationExecutionPlan — the complete structured output of the
   planner stage and the direct input to the migrator stage.  Contains:
     - waves: ordered list of parallel batches (list[list[finding_id]])
     - finding_plans: finding_id → MigrationPlan
     - finding_meta: finding_id → FindingMeta (file, language, lines, deps)

ADR-002: All migration logic is LLM-agentic — no deterministic rewrite path.
ADR-007: LangGraph for orchestration.
"""

from __future__ import annotations

import json
import logging
from collections import deque
from pathlib import Path
from typing import Any

from qsma.llm.client import LLMClient, LLMError
from qsma.planner.state import PlannerState
from qsma.utils.models import (
    Algorithm,
    CryptoFinding,
    FindingMeta,
    MigrationExecutionPlan,
    MigrationPlan,
    MigrationStatus,
)

logger = logging.getLogger(__name__)

# Max findings that can be processed in parallel within one wave.
_MAX_PARALLEL = 6

# NIST target table — informational prompt context only (ADR-002).
# The LLM reasons freely; this table is injected as guidance, not hard rules.
_NIST_TARGETS: dict[str, str] = {
    "RSA": "ML-DSA (Dilithium)  — FIPS 204",
    "ECDSA": "ML-DSA (Dilithium)  — FIPS 204",
    "DSA": "ML-DSA (Dilithium)  — FIPS 204",
    "DH": "ML-DSA (Dilithium)  — FIPS 204",
    "ECDH": "ML-KEM (Kyber)      — FIPS 203",
    "AES-128": "AES-256             — NIST SP 800-131A",
    "DES": "AES-256             — NIST SP 800-131A",
    "3DES": "AES-256             — NIST SP 800-131A",
}


# ---------------------------------------------------------------------------
# Prompt loading
# ---------------------------------------------------------------------------


def _load_system_prompt() -> str:
    prompt_path = (
        Path(__file__).parent.parent / "llm" / "training_data" / "prompts" / "planner_system.txt"
    )
    if prompt_path.exists():
        return prompt_path.read_text(encoding="utf-8").strip()
    return (
        "You are a quantum-safe cryptography migration expert. "
        "Output only valid JSON migration plans."
    )


def _load_few_shot(algorithm: str) -> list[dict[str, Any]]:
    """Load few-shot examples for the given source algorithm, if available."""
    slug_map = {
        "RSA": "rsa_to_ml_dsa",
        "ECDSA": "ecdsa_to_ml_dsa",
        "ECDH": "ecdh_to_ml_kem",
        "AES-128": "aes128_to_aes256",
    }
    slug = slug_map.get(algorithm, "unknown_pattern")
    few_shot_path = (
        Path(__file__).parent.parent / "llm" / "training_data" / "few_shot" / f"{slug}.json"
    )
    if not few_shot_path.exists():
        return []
    try:
        data = json.loads(few_shot_path.read_text(encoding="utf-8"))
        return data.get("examples", [])
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Dependency ordering — topological sort + wave packing
# ---------------------------------------------------------------------------


def _topo_sort_findings(findings: list[CryptoFinding]) -> list[CryptoFinding]:
    """
    Return findings in dependency-safe migration order using Kahn's algorithm.

    Edge semantics from DependencyGraph:
      edges[node_id] = list of node_ids that node_id IMPORTS_FROM (depends on).

    Migration rule: migrate a module BEFORE anything that depends on it.
    i.e. if auth.py imports crypto.py, migrate crypto.py first so that
    when auth.py is migrated its dependency is already quantum-safe.

    Within that constraint, sort by descending blast_radius so that
    high-impact modules are handled earlier.

    If no DependencyGraph data is available (dependency_node_id is None for
    all findings), fall back to descending blast_radius order.
    """
    # Build an index: dependency_node_id → finding
    node_to_finding: dict[str, CryptoFinding] = {}
    for f in findings:
        if f.dependency_node_id:
            node_to_finding[f.dependency_node_id] = f

    # Build in-degree map within the selected finding set only.
    # in_degree[fid] = number of other selected findings that fid depends on
    # (i.e. fid must wait for those to complete before it can be migrated).
    fid_set = {f.id for f in findings}
    finding_by_id = {f.id: f for f in findings}

    # For each finding, collect which OTHER finding_ids it depends on
    # (i.e. the findings whose dependency_node_id appears in this finding's
    # affected_dependency_node_ids — meaning this finding's module imports them).
    # We use affected_dependency_node_ids from the finding itself if available,
    # otherwise we have no edge data and treat all as independent.
    deps_of: dict[str, list[str]] = {f.id: [] for f in findings}

    for f in findings:
        for dep_node_id in f.metadata.get("depends_on_node_ids") or []:
            dep_finding = node_to_finding.get(dep_node_id)
            if dep_finding and dep_finding.id in fid_set and dep_finding.id != f.id:
                deps_of[f.id].append(dep_finding.id)

    in_degree = {fid: len(dep_list) for fid, dep_list in deps_of.items()}
    # reverse map: who is waiting on fid
    dependents_of: dict[str, list[str]] = {fid: [] for fid in fid_set}
    for fid, dep_list in deps_of.items():
        for dep_fid in dep_list:
            dependents_of[dep_fid].append(fid)

    # Kahn's algorithm — process nodes with in_degree==0 first,
    # breaking ties by descending blast_radius
    queue: deque[str] = deque(
        sorted(
            [fid for fid, deg in in_degree.items() if deg == 0],
            key=lambda fid: finding_by_id[fid].blast_radius,
            reverse=True,
        )
    )
    ordered: list[CryptoFinding] = []

    while queue:
        fid = queue.popleft()
        ordered.append(finding_by_id[fid])
        ready = []
        for waiting_fid in dependents_of[fid]:
            in_degree[waiting_fid] -= 1
            if in_degree[waiting_fid] == 0:
                ready.append(waiting_fid)
        # sort newly-ready by descending blast_radius before adding to queue
        ready.sort(key=lambda fid: finding_by_id[fid].blast_radius, reverse=True)
        queue.extend(ready)

    # If there are cycles (shouldn't happen in an import graph but be safe),
    # append remaining findings sorted by descending blast_radius
    if len(ordered) < len(findings):
        remaining_ids = fid_set - {f.id for f in ordered}
        remaining = sorted(
            [finding_by_id[fid] for fid in remaining_ids],
            key=lambda f: f.blast_radius,
            reverse=True,
        )
        ordered.extend(remaining)

    return ordered


def _build_waves(
    ordered: list[CryptoFinding],
    deps_of: dict[str, list[str]],
    max_parallel: int = _MAX_PARALLEL,
) -> list[list[str]]:
    """
    Pack topo-sorted findings into parallel execution waves.

    A finding can join the current wave if all its dependencies are already
    in a completed wave.  Wave size is capped at max_parallel.

    Within each wave, findings that share the same file are sorted by ascending
    line_start so that edits higher in a file are processed before edits lower
    in the same file (avoids line-number drift affecting later edits).
    """
    waves: list[list[str]] = []
    completed: set[str] = set()

    remaining = list(ordered)
    while remaining:
        wave_findings: list[CryptoFinding] = []
        still_waiting: list[CryptoFinding] = []

        for f in remaining:
            if len(wave_findings) >= max_parallel:
                still_waiting.append(f)
                continue
            # All dependencies must be in completed waves
            if all(dep in completed for dep in deps_of.get(f.id, [])):
                wave_findings.append(f)
            else:
                still_waiting.append(f)

        if not wave_findings:
            # No progress possible — remaining have unresolvable deps (cycle guard)
            wave_findings = still_waiting[:max_parallel]
            still_waiting = still_waiting[max_parallel:]

        # Sort within wave: by file path then ascending line_start
        # so top-of-file edits come before bottom-of-file edits in the same file
        wave_findings.sort(key=lambda f: (str(f.location.file), f.location.line_start))

        wave = [f.id for f in wave_findings]
        waves.append(wave)
        completed.update(wave)
        remaining = still_waiting

    return waves


# ---------------------------------------------------------------------------
# Per-finding LLM plan builder
# ---------------------------------------------------------------------------


def _build_plan_for_finding(
    finding: CryptoFinding,
    llm: LLMClient,
    system_prompt: str,
) -> MigrationPlan:
    """
    Call the LLM to produce a MigrationPlan for one finding.
    Works for any language — the LLM sees the snippet and knows the language.
    Falls back to manual_only only if the LLM call or JSON parse fails.
    """
    algorithm_str = finding.algorithm.value
    nist_hint = _NIST_TARGETS.get(algorithm_str, "reason freely using current NIST PQC standards")
    few_shots = _load_few_shot(algorithm_str)
    language = finding.metadata.get("language") or "unknown"

    few_shot_block = ""
    if few_shots:
        few_shot_block = "\n\nFew-shot examples:\n" + json.dumps(few_shots, indent=2)

    snippet = (finding.location.snippet or "").strip()

    user_msg = (
        f"Finding ID: {finding.id}\n"
        f"Language: {language}\n"
        f"Algorithm: {algorithm_str}\n"
        f"Usage type: {finding.usage_type}\n"
        f"NIST suggested target: {nist_hint}\n"
        f"Library: {finding.library or 'unknown'}\n"
        f"Blast radius (modules depending on this): {finding.blast_radius}\n"
        f"File: {finding.location.file} "
        f"(lines {finding.location.line_start}–{finding.location.line_end})\n"
        f"\nCode snippet:\n```{language}\n{snippet}\n```"
        f"{few_shot_block}\n\n"
        "Produce the migration plan JSON now."
    )

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_msg},
    ]

    try:
        raw = llm.chat(messages)
        data = json.loads(raw)
    except (LLMError, json.JSONDecodeError) as exc:
        logger.warning(
            "Planner LLM call failed for %s: %s — falling back to manual_only",
            finding.id,
            exc,
        )
        return MigrationPlan(
            finding_id=finding.id,
            strategy="manual_only",
            target_algorithm=Algorithm.UNKNOWN,
            description=f"LLM call failed: {exc}",
            estimated_complexity="high",
            transformation_hints={"source_algorithm": algorithm_str},
        )

    # Resolve target_algorithm: prefer LLM response, fall back to UNKNOWN
    raw_target = data.get("target_algorithm", "")
    try:
        target_alg = Algorithm(raw_target)
    except ValueError:
        target_alg = Algorithm.UNKNOWN

    hints: dict[str, Any] = data.get("transformation_hints", {})
    # Always inject source_algorithm — migrator depends on this key for few-shot lookup
    hints["source_algorithm"] = algorithm_str

    return MigrationPlan(
        finding_id=finding.id,
        strategy=data.get("strategy", "llm_assisted"),
        target_algorithm=target_alg,
        description=data.get("description", ""),
        estimated_complexity=data.get("estimated_complexity", "medium"),
        requires_dependency_update=bool(data.get("requires_dependency_update", False)),
        new_dependencies=data.get("new_dependencies", []),
        transformation_hints=hints,
        affected_dependency_node_ids=(
            [finding.dependency_node_id] if finding.dependency_node_id else []
        ),
    )


# ---------------------------------------------------------------------------
# LangGraph node
# ---------------------------------------------------------------------------


def planner_node(state: PlannerState) -> PlannerState:
    """
    LangGraph node: produce a MigrationExecutionPlan for all selected findings.

    Steps:
      1. Topological sort findings by dependency order (high blast-radius first).
      2. Pack into parallel waves (max _MAX_PARALLEL per wave).
      3. Call LLM for each finding to produce a MigrationPlan.
      4. Build and store MigrationExecutionPlan on state.
      5. Mirror plans into state.pending_plans and state.migration_order.
    """
    if state.execution_plan is not None:
        # Resume path — planner already ran, skip
        return state

    llm = LLMClient()
    system_prompt = _load_system_prompt()

    # 1. Topological sort
    ordered = _topo_sort_findings(state.selected_findings)

    # Rebuild deps_of for wave packing
    node_to_finding = {
        f.dependency_node_id: f for f in state.selected_findings if f.dependency_node_id
    }
    fid_set = {f.id for f in state.selected_findings}
    deps_of: dict[str, list[str]] = {f.id: [] for f in state.selected_findings}
    for f in state.selected_findings:
        for dep_node_id in f.metadata.get("depends_on_node_ids") or []:
            dep_finding = node_to_finding.get(dep_node_id)
            if dep_finding and dep_finding.id in fid_set and dep_finding.id != f.id:
                deps_of[f.id].append(dep_finding.id)

    # 2. Pack into parallel waves
    waves = _build_waves(ordered, deps_of)

    # 3. LLM plan for each finding
    finding_plans: dict[str, MigrationPlan] = {}
    finding_meta: dict[str, FindingMeta] = {}

    for finding in ordered:
        logger.info(
            "Planner: building plan for %s (%s, %s)",
            finding.id,
            finding.algorithm.value,
            finding.metadata.get("language", "unknown"),
        )
        plan = _build_plan_for_finding(finding, llm, system_prompt)
        finding_plans[finding.id] = plan

    # Build meta with order numbers from the wave-sorted sequence
    order_counter = 1
    for wave in waves:
        for fid in wave:
            f = next(x for x in ordered if x.id == fid)
            plan = finding_plans[fid]
            finding_meta[fid] = FindingMeta(
                finding_id=fid,
                order=order_counter,
                file=f.location.file,
                language=f.metadata.get("language") or "unknown",
                symbol_name=f.metadata.get("symbol_name") or "",
                line_start=f.location.line_start,
                line_end=f.location.line_end,
                algorithm=f.algorithm.value,
                target_algorithm=plan.target_algorithm.value,
                description=f.explanation,
                depends_on=deps_of.get(fid, []),
            )
            order_counter += 1
            f.migration_status = MigrationStatus.IN_PROGRESS

    # 4. Build execution plan
    exec_plan = MigrationExecutionPlan(
        session_id=state.session_id,
        waves=waves,
        finding_plans=finding_plans,
        finding_meta=finding_meta,
    )

    # 5. Store on state
    state.execution_plan = exec_plan
    state.pending_plans = finding_plans
    state.migration_order = [fid for wave in waves for fid in wave]

    return state


# ---------------------------------------------------------------------------
# Convenience entry point for non-LangGraph callers (CLI --auto)
# ---------------------------------------------------------------------------


def run_planner(
    findings: list[CryptoFinding],
    session_id: str,
    target_path: Path,
    dry_run: bool = False,
    llm: LLMClient | None = None,
) -> PlannerState:
    """
    Build a MigrationExecutionPlan for the given findings and return a
    PlannerState ready to hand off to the Migrator.
    """
    state = PlannerState(
        session_id=session_id,
        target_path=target_path,
        selected_findings=findings,
        dry_run=dry_run,
    )
    return planner_node(state)
