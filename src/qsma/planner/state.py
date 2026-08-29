"""
qsma.planner.state
==================
Planner-owned internal state.

PlannerState is the working state for planner_node only.
It is not shared with the Migrator or Validator directly.
planner_node returns a MigrationExecutionPlan (from models.py)
which is the only output that crosses the module boundary.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from qsma.utils.models import (
    CryptoFinding,
    MigrationExecutionPlan,
    MigrationPlan,
)


class PlannerState(BaseModel):
    """
    Internal working state for planner_node.

    Produced by: CLI / agent/graph.py  (initialised before calling planner_node)
    Consumed by: planner_node
    Output:      execution_plan  →  stored in MigrationSessionState for the Migrator
    """
    session_id: str
    target_path: Path

    # Input: findings selected by the user or --auto
    selected_findings: list[CryptoFinding] = Field(default_factory=list)

    # Control
    dry_run: bool = False

    # Output: set by planner_node when planning is complete
    execution_plan: MigrationExecutionPlan | None = None

    # Convenience mirrors populated alongside execution_plan
    pending_plans: dict[str, MigrationPlan] = Field(default_factory=dict)
    migration_order: list[str] = Field(default_factory=list)   # flat ordered list from waves
