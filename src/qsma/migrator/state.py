"""
qsma.migrator.state
===================
Migrator-owned internal state.

MigratorState is the working state for migrator_node only.
Input comes from the MigrationExecutionPlan (Planner output).
Output is a list of TransformationResult objects that cross
the module boundary into the Validator.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field

from qsma.utils.models import (
    MigrationExecutionPlan,
    TransformationResult,
)


class MigratorState(BaseModel):
    """
    Internal working state for migrator_node.

    Produced by: agent/graph.py  (built from MigrationSessionState before calling migrator_node)
    Consumed by: migrator_node
    Output:      transformation_results  →  stored in MigrationSessionState for the Validator
    """

    session_id: str
    target_path: Path

    # Input: execution plan from the Planner
    execution_plan: MigrationExecutionPlan

    # Control
    dry_run: bool = False

    # Per-finding tracking
    current_finding_id: str | None = None
    retry_count: int = 0  # attempts on current finding (reset per finding)
    retry_hints: str | None = None  # plain-text hints from Validator on retry

    # Completion tracking
    completed_findings: list[str] = Field(default_factory=list)  # finding_ids done
    failed_findings: list[str] = Field(default_factory=list)  # finding_ids escalated

    # Output: accumulated results — handed off to Validator when done
    transformation_results: list[TransformationResult] = Field(default_factory=list)

    # Routing signal for agent/graph.py
    routing_signal: str = "pass"  # "validate" | "escalate" | "done"
