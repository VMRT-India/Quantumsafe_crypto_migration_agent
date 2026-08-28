"""
qsma.utils.models
=================
Shared Pydantic data-models (contracts) used across all modules.

ARCHITECTURAL DECISION: These models are the single source of truth for
inter-module data exchange.  Do NOT define competing schema representations
in individual modules.  If a schema must change, update here and propagate.

See docs/contracts/ for the full contract specifications.
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class QuantumRisk(str, Enum):
    """NIST-aligned quantum vulnerability classification."""
    CRITICAL = "CRITICAL"   # Broken by Shor's algorithm (RSA, ECC, DH)
    HIGH     = "HIGH"       # Weakened — key sizes insufficient post-quantum
    MEDIUM   = "MEDIUM"     # Indirect exposure or algorithm-dependent
    LOW      = "LOW"        # Quantum-safe or minimal exposure
    INFO     = "INFO"       # Informational; no direct vulnerability


class Algorithm(str, Enum):
    """Known cryptographic algorithms tracked by the detector."""
    # Quantum-vulnerable
    RSA         = "RSA"
    ECDSA       = "ECDSA"
    ECDH        = "ECDH"
    DSA         = "DSA"
    DH          = "DH"
    # Symmetric (partial concern — key size dependent)
    AES_128     = "AES-128"
    AES_256     = "AES-256"
    DES         = "DES"
    TRIPLE_DES  = "3DES"
    # Hashing
    MD5         = "MD5"
    SHA1        = "SHA-1"
    SHA256      = "SHA-256"
    SHA384      = "SHA-384"
    SHA512      = "SHA-512"
    # Post-quantum (migration targets)
    KYBER       = "ML-KEM (Kyber)"
    DILITHIUM   = "ML-DSA (Dilithium)"
    FALCON      = "FN-DSA (Falcon)"
    SPHINCS     = "SLH-DSA (SPHINCS+)"
    # Unknown
    UNKNOWN     = "UNKNOWN"


class MigrationStatus(str, Enum):
    PENDING    = "pending"
    SELECTED   = "selected"
    IN_PROGRESS = "in_progress"
    COMPLETED  = "completed"
    FAILED     = "failed"
    SKIPPED    = "skipped"


# ---------------------------------------------------------------------------
# Core domain models
# ---------------------------------------------------------------------------

class CodeLocation(BaseModel):
    """Precise location of a finding in the source code."""
    file: Path
    line_start: int
    line_end: int
    column_start: int | None = None
    column_end: int | None = None
    snippet: str | None = None          # Short code excerpt for display


class CryptoFinding(BaseModel):
    """
    A single detected cryptographic usage site.
    Produced by: Detector → Classifier
    Consumed by: Planner, Reporter, Migrator
    """
    id: str                             # Stable unique ID, e.g. "QSMA-0001"
    algorithm: Algorithm
    risk: QuantumRisk
    location: CodeLocation
    usage_type: str                     # e.g. "key_exchange", "signature", "encryption"
    library: str | None = None          # e.g. "cryptography", "OpenSSL", "hashlib"
    severity_score: float = Field(ge=0.0, le=10.0, default=0.0)
    explanation: str                    # Human-readable reason for the risk
    recommendation: str                 # Suggested replacement
    migration_status: MigrationStatus = MigrationStatus.PENDING
    metadata: dict[str, Any] = Field(default_factory=dict)


class MigrationPlan(BaseModel):
    """
    A migration plan for a single finding.
    Produced by: Planner
    Consumed by: Migrator
    """
    finding_id: str
    strategy: str                       # e.g. "deterministic_rewrite", "llm_assisted"
    target_algorithm: Algorithm
    description: str
    estimated_complexity: str           # "low" | "medium" | "high"
    requires_dependency_update: bool = False
    new_dependencies: list[str] = Field(default_factory=list)
    transformation_hints: dict[str, Any] = Field(default_factory=dict)


class TransformationResult(BaseModel):
    """
    Result of applying a MigrationPlan to source code.
    Produced by: Migrator
    Consumed by: Validator, Reporter
    """
    finding_id: str
    success: bool
    original_snippet: str | None = None
    transformed_snippet: str | None = None
    files_modified: list[Path] = Field(default_factory=list)
    error_message: str | None = None


class ValidationResult(BaseModel):
    """
    Result of post-migration validation.
    Produced by: Validator
    Consumed by: Reporter
    """
    passed: bool
    build_ok: bool | None = None
    tests_ok: bool | None = None
    test_summary: str | None = None
    regressions: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    error_output: str | None = None


class ScanReport(BaseModel):
    """
    Top-level scan report returned by the full pipeline.
    Produced by: Reporter
    """
    target_path: Path
    findings: list[CryptoFinding] = Field(default_factory=list)
    total_files_scanned: int = 0
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    transformation_results: list[TransformationResult] = Field(default_factory=list)
    validation_result: ValidationResult | None = None
    scan_duration_seconds: float = 0.0
