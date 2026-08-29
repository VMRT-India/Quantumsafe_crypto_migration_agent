"""
qsma.validator.state
====================
Validator-owned internal state.

ValidatorState matches the exact field shape that Palak's validator_node
(src/qsma/validator/node.py) reads and writes.  The Migrator produces
this state as its final output so it can be handed directly to the Validator
with no adapter or field translation.

Fields marked with (validator reads) are consumed by validator_node.
Fields marked with (validator writes) are set by validator_node as output.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field

from qsma.utils.models import (
    CryptoFinding,
    TransformationResult,
    ValidationResult,
)


class ValidatorState(BaseModel):
    """
    Input/output state for Palak's validator_node.

    The Migrator builds and populates this at the end of each finding's
    transformation, then hands it to validator_node.

    Produced by: Migrator  (migrator_node fills all fields before handing off)
    Consumed by: validator_node
    """

    # ── Session identity ─────────────────────────────────────────────────
    session_id: str  # (validator reads)
    target_path: Path  # (validator reads) — where to run pytest

    # ── Finding context ───────────────────────────────────────────────────
    # Full list of selected findings — validator looks up by current_finding_id
    findings: list[CryptoFinding] = Field(default_factory=list)  # (validator reads)
    current_finding_id: str | None = None  # (validator reads)

    # ── Retry control ─────────────────────────────────────────────────────
    current_attempt: int = 0  # (validator reads + writes)
    max_attempts: int = 3  # (validator reads)
    retry_hints: str | None = None  # (validator writes on failure)

    # ── Transformation input ──────────────────────────────────────────────
    # Results from the Migrator — validator checks files_modified for syntax
    transformation_results: list[TransformationResult] = Field(
        default_factory=list
    )  # (validator reads)

    # ── Validation output ─────────────────────────────────────────────────
    validation_results: list[ValidationResult] = Field(default_factory=list)  # (validator writes)

    # ── Control ───────────────────────────────────────────────────────────
    is_dry_run: bool = False  # (validator reads) — skip validation if True
