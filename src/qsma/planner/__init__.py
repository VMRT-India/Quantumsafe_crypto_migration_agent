"""
qsma.planner
============
LangGraph node: planner_node

Receives selected CryptoFindings from MigrationSessionState and produces a
MigrationPlan for each finding by calling the LLM.

Entry point for the LangGraph agent graph (src/qsma/agent/graph.py).
Direct usage (outside LangGraph, e.g. CLI --auto) is also supported via
run_planner().

ADR-002: All migration logic is LLM-agentic — no deterministic rewrite path.
ADR-007: LangGraph for orchestration.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from qsma.llm.client import LLMClient, LLMError
from qsma.utils.models import (
    Algorithm,
    CryptoFinding,
    MigrationPlan,
    MigrationSessionState,
    MigrationStatus,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# NIST target table — provided as context in the LLM prompt, not hard-coded
# rules (ADR-002).  This mapping is informational for the prompt builder only.
# ---------------------------------------------------------------------------

_NIST_TARGET_MAP: dict[str, str] = {
    Algorithm.RSA:        Algorithm.DILITHIUM,
    Algorithm.ECDSA:      Algorithm.DILITHIUM,
    Algorithm.DSA:        Algorithm.DILITHIUM,
    Algorithm.DH:         Algorithm.DILITHIUM,
    Algorithm.ECDH:       Algorithm.KYBER,
    Algorithm.AES_128:    Algorithm.AES_256,
    Algorithm.DES:        Algorithm.AES_256,
    Algorithm.TRIPLE_DES: Algorithm.AES_256,
}

# Languages supported for automated (LLM) migration.  All others → manual_only.
_AUTOMATED_LANGUAGES = {"python"}


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
    """Load few-shot examples for a given source algorithm, if available."""
    slug_map = {
        "RSA":    "rsa_to_ml_dsa",
        "ECDSA":  "ecdsa_to_ml_dsa",
        "ECDH":   "ecdh_to_ml_kem",
        "AES-128": "aes128_to_aes256",
    }
    slug = slug_map.get(algorithm, "unknown_pattern")
    few_shot_path = (
        Path(__file__).parent.parent
        / "llm" / "training_data" / "few_shot" / f"{slug}.json"
    )
    if not few_shot_path.exists():
        return []
    try:
        data = json.loads(few_shot_path.read_text(encoding="utf-8"))
        return data.get("examples", [])
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Core plan builder
# ---------------------------------------------------------------------------

def _build_plan_for_finding(
    finding: CryptoFinding,
    llm: LLMClient,
    system_prompt: str,
) -> MigrationPlan:
    """
    Produce a MigrationPlan for one finding.

    - Non-Python findings → manual_only immediately (no LLM call).
    - Python findings → call LLM; parse JSON response into MigrationPlan.
    """
    language = (finding.metadata.get("language") or "python").lower()

    # Non-Python: no automated migration in MVP
    if language not in _AUTOMATED_LANGUAGES:
        return MigrationPlan(
            finding_id=finding.id,
            strategy="manual_only",
            target_algorithm=Algorithm.UNKNOWN,
            description=f"Automated migration not supported for language '{language}' in MVP.",
            estimated_complexity="high",
            requires_dependency_update=False,
        )

    algorithm_str = finding.algorithm.value
    suggested_target = _NIST_TARGET_MAP.get(finding.algorithm, Algorithm.UNKNOWN)
    few_shots = _load_few_shot(algorithm_str)

    few_shot_block = ""
    if few_shots:
        few_shot_block = "\n\nFew-shot examples:\n" + json.dumps(few_shots, indent=2)

    snippet = (finding.location.snippet or "").strip()

    user_msg = (
        f"Finding ID: {finding.id}\n"
        f"Algorithm: {algorithm_str}\n"
        f"Usage type: {finding.usage_type}\n"
        f"Suggested NIST target: {suggested_target}\n"
        f"Library: {finding.library or 'unknown'}\n"
        f"Blast radius (transitive dependents): {finding.blast_radius}\n"
        f"File: {finding.location.file} "
        f"(lines {finding.location.line_start}–{finding.location.line_end})\n"
        f"\nCode snippet:\n```python\n{snippet}\n```"
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
        logger.warning("Planner LLM call failed for %s: %s — falling back to manual_only", finding.id, exc)
        return MigrationPlan(
            finding_id=finding.id,
            strategy="manual_only",
            target_algorithm=Algorithm.UNKNOWN,
            description=f"LLM call failed: {exc}",
            estimated_complexity="high",
        )

    # Resolve target_algorithm: prefer LLM response, fall back to NIST table
    raw_target = data.get("target_algorithm", "")
    try:
        target_alg = Algorithm(raw_target)
    except ValueError:
        target_alg = Algorithm(suggested_target) if suggested_target != Algorithm.UNKNOWN else Algorithm.UNKNOWN

    return MigrationPlan(
        finding_id=finding.id,
        strategy=data.get("strategy", "llm_assisted"),
        target_algorithm=target_alg,
        description=data.get("description", ""),
        estimated_complexity=data.get("estimated_complexity", "medium"),
        requires_dependency_update=bool(data.get("requires_dependency_update", False)),
        new_dependencies=data.get("new_dependencies", []),
        transformation_hints=data.get("transformation_hints", {}),
        affected_dependency_node_ids=(
            [finding.dependency_node_id] if finding.dependency_node_id else []
        ),
    )


# ---------------------------------------------------------------------------
# LangGraph node
# ---------------------------------------------------------------------------

def planner_node(state: MigrationSessionState) -> MigrationSessionState:
    """
    LangGraph node: plan migrations for all un-planned selected findings.

    Reads state.selected_findings, skips findings that already have a plan
    in state.pending_plans, calls the LLM for the rest.
    """
    llm = LLMClient()
    system_prompt = _load_system_prompt()

    for finding in state.selected_findings:
        if finding.id in state.pending_plans:
            continue  # already planned (resume path)

        logger.info("Planner: building plan for finding %s (%s)", finding.id, finding.algorithm)
        plan = _build_plan_for_finding(finding, llm, system_prompt)
        state.pending_plans[finding.id] = plan
        finding.migration_status = MigrationStatus.SELECTED

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
) -> MigrationSessionState:
    """
    Build plans for the given findings and return an initialised
    MigrationSessionState ready to hand to the migrator.
    """
    state = MigrationSessionState(
        session_id=session_id,
        target_path=target_path,
        selected_findings=findings,
        dry_run=dry_run,
    )
    _llm = llm or LLMClient()
    system_prompt = _load_system_prompt()

    for finding in findings:
        plan = _build_plan_for_finding(finding, _llm, system_prompt)
        state.pending_plans[finding.id] = plan

    return state
