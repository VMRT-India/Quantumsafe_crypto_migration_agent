"""
qsma.agent.graph — LangGraph StateGraph wiring

Orchestrates the three pipeline stages already implemented as LangGraph-style
nodes:

    planner_node   (qsma.planner)   — runs once, produces MigrationExecutionPlan
    migrator_node  (qsma.migrator)  — transforms the current finding's code
    validator_node (qsma.validator) — syntax check + test run + retry hints

Graph shape
-----------
    START -> planner -> migrator --[validate]--> validator --[retry]--> migrator
                            |                         |
                       [escalate]                 [advance]
                            v                         v
                         advance <--------------------+
                            |
                      [next]  -> migrator (next finding)
                      [done]  -> END

`advance` moves to the next pending finding (or END if none remain) and
resets per-finding retry bookkeeping. `migrator` also routes straight to END
via "done" when there is no pending finding left when it is entered directly
(covers the initial empty-selection case).

State: MigrationSessionState (qsma/utils/models.py) — the only data that
crosses stage boundaries, per the contract docstring on that model. Retry
bookkeeping that is internal to a single finding's attempt loop (retry_count,
retry_hints, migration_order, completed/failed lists) is NOT part of that
contract (by design — see MigrationSessionState docstring) and is tracked
separately per session_id in `_RUNTIME` here, mirroring MigratorState's own
internal fields.

Checkpointer: none (in-memory graph execution only) — Redis-backed
persistence (ADR-008) is a stretch goal; `qsma.utils.session` provides the
save/get/delete surface for --resume within a single process.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from langgraph.graph import END, StateGraph

from qsma.migrator import migrator_node
from qsma.migrator.state import MigratorState
from qsma.planner import planner_node
from qsma.planner.state import PlannerState
from qsma.utils.models import CryptoFinding, MigrationSessionState
from qsma.utils.session import get_session, save_session
from qsma.validator.node import validator_node
from qsma.validator.state import ValidatorState

logger = logging.getLogger(__name__)

_MAX_RETRIES = 3

# Per-session runtime bookkeeping — internal to the migrator/validator retry
# loop, deliberately kept out of MigrationSessionState (see module docstring).
_RUNTIME: dict[str, dict[str, Any]] = {}


def _init_runtime(session_id: str, findings: list[CryptoFinding], dry_run: bool) -> None:
    _RUNTIME[session_id] = {
        "findings_lookup": {f.id: f for f in findings},
        "migration_order": [],  # filled in by _planner_step
        "completed": [],
        "failed": [],
        "retry_count": 0,
        "retry_hints": None,
        "dry_run": dry_run,
    }


def _next_pending_finding(session_id: str) -> str | None:
    rt = _RUNTIME[session_id]
    for fid in rt["migration_order"]:
        if fid not in rt["completed"] and fid not in rt["failed"]:
            return str(fid)
    return None


# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------


def _planner_step(state: MigrationSessionState) -> dict[str, Any]:
    if state.execution_plan is not None:
        return {}

    rt = _RUNTIME[state.session_id]
    planner_state = PlannerState(
        session_id=state.session_id,
        target_path=state.target_path,
        selected_findings=list(rt["findings_lookup"].values()),
        dry_run=rt["dry_run"],
    )
    result = planner_node(planner_state)
    rt["migration_order"] = result.migration_order
    return {"execution_plan": result.execution_plan}


def _migrator_step(state: MigrationSessionState) -> dict[str, Any]:
    rt = _RUNTIME[state.session_id]
    current_finding_id = state.current_finding_id or _next_pending_finding(state.session_id)

    if current_finding_id is None or state.execution_plan is None:
        return {"routing_signal": "done"}

    migrator_state = MigratorState(
        session_id=state.session_id,
        target_path=state.target_path,
        execution_plan=state.execution_plan,
        dry_run=rt["dry_run"],
        current_finding_id=current_finding_id,
        retry_count=rt["retry_count"],
        retry_hints=rt["retry_hints"],
        completed_findings=list(rt["completed"]),
        failed_findings=list(rt["failed"]),
        transformation_results=list(state.transformation_results),
    )
    migrator_state = migrator_node(migrator_state)

    rt["completed"] = migrator_state.completed_findings
    rt["failed"] = migrator_state.failed_findings

    return {
        "current_finding_id": current_finding_id,
        "transformation_results": migrator_state.transformation_results,
        "routing_signal": migrator_state.routing_signal,  # "validate" | "escalate" | "done"
    }


def _validator_step(state: MigrationSessionState) -> dict[str, Any]:
    rt = _RUNTIME[state.session_id]
    validator_state = ValidatorState(
        session_id=state.session_id,
        target_path=state.target_path,
        findings=list(rt["findings_lookup"].values()),
        current_finding_id=state.current_finding_id,
        current_attempt=rt["retry_count"],
        max_attempts=_MAX_RETRIES,
        retry_hints=rt["retry_hints"],
        transformation_results=list(state.transformation_results),
        validation_results=list(state.validation_results),
        is_dry_run=rt["dry_run"],
    )
    updates = validator_node(validator_state)

    new_validation_results = updates.get("validation_results", state.validation_results)
    rt["retry_count"] = updates.get("current_attempt", rt["retry_count"])
    rt["retry_hints"] = updates.get("retry_hints")

    # validator_node sets retry_hints only on the "needs another attempt"
    # branch — both the pass branch and the permanent-failure branch clear it.
    if rt["retry_hints"]:
        routing_signal = "retry"
    else:
        latest = new_validation_results[-1] if new_validation_results else None
        if latest is not None and latest.passed:
            rt["completed"].append(state.current_finding_id)
        else:
            rt["failed"].append(state.current_finding_id)
        routing_signal = "advance"

    return {"validation_results": new_validation_results, "routing_signal": routing_signal}


def _advance_step(state: MigrationSessionState) -> dict[str, Any]:
    rt = _RUNTIME[state.session_id]
    fid = state.current_finding_id
    if fid and fid not in rt["completed"] and fid not in rt["failed"]:
        rt["failed"].append(fid)  # migrator escalated without ever reaching validation

    rt["retry_count"] = 0
    rt["retry_hints"] = None
    next_fid = _next_pending_finding(state.session_id)

    return {
        "current_finding_id": next_fid,
        "routing_signal": "next" if next_fid is not None else "done",
    }


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------


def build_graph() -> Any:
    graph = StateGraph(MigrationSessionState)
    graph.add_node("planner", _planner_step)
    graph.add_node("migrator", _migrator_step)
    graph.add_node("validator", _validator_step)
    graph.add_node("advance", _advance_step)

    graph.set_entry_point("planner")
    graph.add_edge("planner", "migrator")

    graph.add_conditional_edges(
        "migrator",
        lambda s: s.routing_signal,
        {"validate": "validator", "escalate": "advance", "done": END},
    )
    graph.add_conditional_edges(
        "validator",
        lambda s: s.routing_signal,
        {"retry": "migrator", "advance": "advance"},
    )
    graph.add_conditional_edges(
        "advance",
        lambda s: s.routing_signal,
        {"next": "migrator", "done": END},
    )

    return graph.compile()


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def run_migration_session(
    session_id: str,
    target_path: Path,
    selected_findings: list[CryptoFinding],
    dry_run: bool = False,
) -> MigrationSessionState:
    """
    Run (or resume) a full migration session: Planner -> {Migrator <-> Validator}*
    over every selected finding.

    Parameters
    ----------
    session_id: stable id — pass the same id to --resume within this process.
    target_path: codebase root (also where the Validator runs pytest).
    selected_findings: findings the user chose to migrate.
    dry_run: skip real file writes / test execution (planner + migrator +
             validator all respect this).
    """
    existing = get_session(session_id)
    if existing is not None:
        logger.info("Resuming session %s", session_id)
        state = existing
    else:
        state = MigrationSessionState(session_id=session_id, target_path=target_path)

    _init_runtime(session_id, selected_findings, dry_run)

    compiled = build_graph()
    result_dict = compiled.invoke(state)
    final_state = MigrationSessionState.model_validate(result_dict)

    save_session(final_state)
    _RUNTIME.pop(session_id, None)
    return final_state


__all__ = ["build_graph", "run_migration_session"]
