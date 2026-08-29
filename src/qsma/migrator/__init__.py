"""
qsma.migrator
=============
LangGraph node: migrator_node

Reads a MigrationExecutionPlan (from PlannerState) and transforms each
source file using the LLM, then patches it via patcher.py.

Output: ValidatorState — built directly in the shape Palak's validator_node
expects.  No adapter needed.  The migrator is responsible for filling every
field the validator reads.

Sub-modules:
  migrator/llm_transform.py — prompt builder + LLM response parser
  migrator/patcher.py       — line-range file patcher (atomic write)
  migrator/state.py         — MigratorState (migrator-internal)

ADR-002: All transformation logic is LLM-driven — no deterministic rewrite.
ADR-003: patcher.py is a file-write utility, not migration logic.
ADR-007: LangGraph for orchestration.
"""

from __future__ import annotations

import logging
from pathlib import Path

from qsma.llm.client import LLMClient
from qsma.migrator.llm_transform import call_llm_transform
from qsma.migrator.patcher import apply_patch
from qsma.migrator.state import MigratorState
from qsma.utils.models import (
    MigrationExecutionPlan,
    MigrationStatus,
    TransformationResult,
)
from qsma.validator.state import ValidatorState

logger = logging.getLogger(__name__)

_MAX_RETRIES = 3


# ---------------------------------------------------------------------------
# LangGraph node
# ---------------------------------------------------------------------------

def migrator_node(state: MigratorState) -> MigratorState:
    """
    LangGraph node: transform the current finding in state.

    Reads state.current_finding_id (set by agent/graph.py router).
    On exit sets state.routing_signal:
      "validate"  — transformation succeeded, hand to validator_node
      "escalate"  — manual_only / max retries / patch failure
      "done"      — no current_finding_id set
    """
    finding_id = state.current_finding_id
    if not finding_id:
        logger.warning("migrator_node called with no current_finding_id — skipping")
        state.routing_signal = "done"
        return state

    plan = state.execution_plan.finding_plans.get(finding_id)
    meta = state.execution_plan.finding_meta.get(finding_id)

    if not plan:
        logger.error("No plan found for finding %s", finding_id)
        state.transformation_results.append(TransformationResult(
            finding_id=finding_id, success=False,
            error_message="No migration plan available.",
        ))
        state.routing_signal = "escalate"
        return state

    # manual_only — no LLM call
    if plan.strategy == "manual_only":
        state.transformation_results.append(TransformationResult(
            finding_id=finding_id, success=False,
            error_message=f"manual_only: {plan.description}",
        ))
        state.routing_signal = "escalate"
        return state

    # Max retries exceeded
    if state.retry_count >= _MAX_RETRIES:
        logger.warning("Max retries (%d) reached for %s", _MAX_RETRIES, finding_id)
        state.transformation_results.append(TransformationResult(
            finding_id=finding_id, success=False,
            error_message=f"Max retries ({_MAX_RETRIES}) exceeded.",
            original_snippet=meta.description if meta else None,
        ))
        state.failed_findings.append(finding_id)
        state.routing_signal = "escalate"
        return state

    # Get original snippet from plan meta or finding hint
    original_snippet = (meta and (
        # prefer the actual snippet from the plan hints if available
        plan.transformation_hints.get("original_snippet") or meta.description
    )) or ""

    # Call LLM
    llm = LLMClient()
    retry_hints = state.retry_hints if state.retry_count > 0 else None
    success, transformed = call_llm_transform(plan, original_snippet, llm, {"hint": retry_hints} if retry_hints else None)

    if not success:
        state.transformation_results.append(TransformationResult(
            finding_id=finding_id, success=False,
            original_snippet=original_snippet,
            error_message=transformed,
        ))
        state.failed_findings.append(finding_id)
        state.routing_signal = "escalate"
        return state

    # Patch source file
    files_modified: list[Path] = []
    patch_success = True
    patch_detail = ""

    if meta and meta.file:
        patch_ok, patch_detail = apply_patch(
            source_path=Path(meta.file),
            replacement_code=transformed,
            line_start=meta.line_start,
            line_end=meta.line_end,
            dry_run=state.dry_run,
        )
        if patch_ok:
            files_modified.append(Path(meta.file))
        else:
            patch_success = False

    result = TransformationResult(
        finding_id=finding_id,
        success=patch_success,
        original_snippet=original_snippet,
        transformed_snippet=transformed,
        files_modified=files_modified,
        error_message=patch_detail if not patch_success else None,
    )
    state.transformation_results.append(result)

    if patch_success:
        state.completed_findings.append(finding_id)
        state.routing_signal = "validate"
    else:
        state.failed_findings.append(finding_id)
        state.routing_signal = "escalate"

    return state


# ---------------------------------------------------------------------------
# Build ValidatorState — migrator's final output, validator's direct input
# ---------------------------------------------------------------------------

def build_validator_state(
    migrator_state: MigratorState,
    findings_lookup: dict,   # finding_id → CryptoFinding, from PlannerState.selected_findings
) -> ValidatorState:
    """
    Convert MigratorState into ValidatorState — the exact shape Palak's
    validator_node reads.  Called by agent/graph.py after migrator_node completes
    a finding, or by run_migrator() for the CLI --auto path.
    """
    from qsma.utils.models import CryptoFinding

    return ValidatorState(
        session_id=migrator_state.session_id,
        target_path=migrator_state.target_path,
        findings=list(findings_lookup.values()),
        current_finding_id=migrator_state.current_finding_id,
        current_attempt=migrator_state.retry_count,
        max_attempts=_MAX_RETRIES,
        retry_hints=migrator_state.retry_hints,
        transformation_results=migrator_state.transformation_results,
        validation_results=[],
        is_dry_run=migrator_state.dry_run,
    )


# ---------------------------------------------------------------------------
# Convenience entry point (CLI --auto, outside LangGraph)
# ---------------------------------------------------------------------------

def run_migrator(
    planner_state: "PlannerState",    # type: ignore[name-defined]  — avoid circular import
    dry_run: bool = False,
) -> tuple[MigratorState, ValidatorState]:
    """
    Process all findings in planner_state.execution_plan sequentially.
    Returns (MigratorState, ValidatorState) — the latter is ready to pass
    directly to validator_node.

    No retry loop here — for retry behaviour use the LangGraph graph.
    """
    from qsma.planner.state import PlannerState  # local import avoids circular

    exec_plan: MigrationExecutionPlan = planner_state.execution_plan
    findings_lookup = {f.id: f for f in planner_state.selected_findings}

    state = MigratorState(
        session_id=planner_state.session_id,
        target_path=planner_state.target_path,
        execution_plan=exec_plan,
        dry_run=dry_run,
    )

    # Walk migration_order (flat, already wave-sorted)
    for finding_id in planner_state.migration_order:
        if finding_id in state.completed_findings or finding_id in state.failed_findings:
            continue
        state.current_finding_id = finding_id
        state.retry_count = 0
        state.retry_hints = None
        state = migrator_node(state)

    validator_state = build_validator_state(state, findings_lookup)
    return state, validator_state
