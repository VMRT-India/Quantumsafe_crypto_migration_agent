"""
qsma.migrator
=============
LangGraph node: migrator_node

Receives a MigrationSessionState (with pending_plans from the Planner) and
transforms each source file using the LLM, then patches it with libcst.

Sub-modules:
  migrator/llm_transform.py — prompt builder + LLM response parser
  migrator/patcher.py       — libcst-based file patcher (atomic write)

ADR-002: All transformation logic is LLM-driven — no deterministic rewrite.
ADR-003: libcst is used only for file splicing, not for migration logic.
ADR-007: LangGraph for orchestration.
"""

from __future__ import annotations

import logging
from pathlib import Path

from qsma.llm.client import LLMClient
from qsma.migrator.llm_transform import call_llm_transform
from qsma.migrator.patcher import apply_patch
from qsma.utils.models import (
    MigrationSessionState,
    MigrationStatus,
    TransformationResult,
)

logger = logging.getLogger(__name__)

_MAX_RETRIES = 3  # hard cap per finding; Validator drives actual retry logic


def migrator_node(state: MigrationSessionState) -> MigrationSessionState:
    """
    LangGraph node: transform the current finding in state.

    Processes state.current_finding_id (set by the graph router).
    On entry:
      - state.pending_plans[current_finding_id] must exist.
      - state.retry_count tracks how many attempts have been made.
      - state.retry_hints carries Validator feedback on retries.

    On exit:
      - Appends a TransformationResult to state.transformation_results.
      - Sets state.routing_signal = "validate" to hand off to validator_node.
      - On non-Python / manual_only: sets routing_signal = "escalate".
    """
    finding_id = state.current_finding_id
    if not finding_id:
        logger.warning("migrator_node called with no current_finding_id — skipping")
        state.routing_signal = "done"
        return state

    plan = state.pending_plans.get(finding_id)
    if not plan:
        logger.error("No plan found for finding %s", finding_id)
        state.transformation_results.append(
            TransformationResult(
                finding_id=finding_id,
                success=False,
                error_message="No migration plan available.",
            )
        )
        state.routing_signal = "escalate"
        return state

    # Locate the finding object
    finding = next((f for f in state.selected_findings if f.id == finding_id), None)

    # manual_only → no LLM call needed
    if plan.strategy == "manual_only":
        result = TransformationResult(
            finding_id=finding_id,
            success=False,
            error_message=f"manual_only: {plan.description}",
        )
        state.transformation_results.append(result)
        if finding:
            finding.migration_status = MigrationStatus.SKIPPED
        state.routing_signal = "escalate"
        return state

    if state.retry_count >= _MAX_RETRIES:
        logger.warning("Max retries (%d) reached for finding %s", _MAX_RETRIES, finding_id)
        result = TransformationResult(
            finding_id=finding_id,
            success=False,
            error_message=f"Max retries ({_MAX_RETRIES}) exceeded.",
            original_snippet=finding.location.snippet if finding else None,
        )
        state.transformation_results.append(result)
        if finding:
            finding.migration_status = MigrationStatus.FAILED
        state.routing_signal = "escalate"
        return state

    # Determine snippet to transform
    original_snippet = (finding.location.snippet or "") if finding else ""
    if not original_snippet:
        logger.warning("No snippet available for finding %s — using empty string", finding_id)

    if finding:
        finding.migration_status = MigrationStatus.IN_PROGRESS

    # Call LLM
    llm = LLMClient()
    retry_hints = state.retry_hints if state.retry_count > 0 else None
    success, transformed = call_llm_transform(plan, original_snippet, llm, retry_hints)

    if not success:
        result = TransformationResult(
            finding_id=finding_id,
            success=False,
            original_snippet=original_snippet,
            error_message=transformed,
        )
        state.transformation_results.append(result)
        if finding:
            finding.migration_status = MigrationStatus.FAILED
        state.routing_signal = "escalate"
        return state

    # Apply patch to source file
    files_modified: list[Path] = []
    patch_success = True
    patch_detail = ""

    if finding and finding.location.file:
        source_path = Path(finding.location.file)
        patch_ok, patch_detail = apply_patch(
            source_path=source_path,
            replacement_code=transformed,
            line_start=finding.location.line_start,
            line_end=finding.location.line_end,
            dry_run=state.dry_run,
        )
        if patch_ok:
            files_modified.append(source_path)
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
        state.routing_signal = "validate"
    else:
        if finding:
            finding.migration_status = MigrationStatus.FAILED
        state.routing_signal = "escalate"

    return state


# ---------------------------------------------------------------------------
# Convenience entry point (CLI --auto, outside LangGraph)
# ---------------------------------------------------------------------------

def run_migrator(state: MigrationSessionState) -> MigrationSessionState:
    """
    Process all pending plans sequentially (no LangGraph graph required).

    Iterates through every finding in state.pending_plans that has not been
    completed or failed, runs migrator_node for each, and returns the final
    state.  Validator feedback / retry is NOT applied here — for full retry
    behaviour use the LangGraph agent graph.
    """
    processed = set(state.completed_findings) | set(state.failed_findings)

    for finding_id in list(state.pending_plans.keys()):
        if finding_id in processed:
            continue
        state.current_finding_id = finding_id
        state.retry_count = 0
        state.retry_hints = {}
        state = migrator_node(state)

    return state
