"""
qsma.utils.models
=================
Shared Pydantic data-models (contracts) used across all modules.
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

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Algorithm(str, Enum):
    """Known cryptographic algorithms tracked by the detector."""

    RSA = "RSA"
    ECDSA = "ECDSA"
    ECDH = "ECDH"
    DSA = "DSA"
    DH = "DH"
    AES_128 = "AES-128"
    AES_256 = "AES-256"
    DES = "DES"
    TRIPLE_DES = "3DES"
    MD5 = "MD5"
    SHA1 = "SHA-1"
    SHA256 = "SHA-256"
    SHA384 = "SHA-384"
    SHA512 = "SHA-512"
    KYBER = "ML-KEM (Kyber)"
    DILITHIUM = "ML-DSA (Dilithium)"
    FALCON = "FN-DSA (Falcon)"
    SPHINCS = "SLH-DSA (SPHINCS+)"
    UNKNOWN = "UNKNOWN"


class MigrationStatus(str, Enum):
    PENDING = "pending"
    SELECTED = "selected"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


# ---------------------------------------------------------------------------
# Ingestion & Analyzer models
# ---------------------------------------------------------------------------


class IngestionConfig(BaseModel):
    exclude_patterns: list[str] = Field(
        default_factory=lambda: ["*.pyc", "__pycache__", ".git", ".venv", "venv", "node_modules"]
    )
    allowed_extensions: list[str] = Field(
        default_factory=lambda: [".py", ".java", ".go", ".c", ".cpp", ".rs", ".h"]
    )
    max_file_size_bytes: int = 1_000_000


class SourceFile(BaseModel):
    path: Path
    content: str
    language: str


class CodebaseSnapshot(BaseModel):
    root_path: Path
    files: list[SourceFile] = Field(default_factory=list)
    file_count: int = 0


class ImportRef(BaseModel):
    module: str
    alias: str | None = None
    line: int
    language: str


class CallSite(BaseModel):
    function_name: str
    arguments: list[str] = Field(default_factory=list)
    line: int
    enclosing_function: str | None = None
    language: str


class ParsedFile(BaseModel):
    path: Path
    language: str
    ts_tree: Any | None = None
    cst_tree: Any | None = None
    imports: list[ImportRef] = Field(default_factory=list)
    call_sites: list[CallSite] = Field(default_factory=list)


class AnalysisResult(BaseModel):
    files: list[ParsedFile] = Field(default_factory=list)
    import_index: dict[str, list[str]] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Dependency graph models
# ---------------------------------------------------------------------------


class DependencyNode(BaseModel):
    node_id: str
    module_name: str
    file: Path
    language: str
    has_crypto: bool = False
    direct_dependents: list[str] = Field(default_factory=list)
    transitive_dependents: list[str] = Field(default_factory=list)


class DependencyGraph(BaseModel):
    session_id: str
    nodes: dict[str, DependencyNode] = Field(default_factory=dict)
    edges: dict[str, list[str]] = Field(default_factory=dict)

    def blast_radius(self, node_id: str) -> int:
        node = self.nodes.get(node_id)
        if node is None:
            return 0
        return len(node.transitive_dependents)


# ---------------------------------------------------------------------------
# Detection models
# ---------------------------------------------------------------------------


class DetectionRule(BaseModel):
    rule_id: str
    algorithm_hint: str
    usage_type: str


class CodeLocation(BaseModel):
    """Precise location of a finding in the source code."""

    file: Path
    line_start: int
    line_end: int
    column_start: int | None = None
    column_end: int | None = None
    snippet: str | None = None


class CryptoHit(BaseModel):
    rule_id: str
    algorithm_hint: str
    usage_type: str
    location: CodeLocation
    raw_node_info: dict[str, Any] = Field(default_factory=dict)
    dependency_node_id: str | None = None


# ---------------------------------------------------------------------------
# Classification models
# ---------------------------------------------------------------------------


class CryptoFinding(BaseModel):
    id: str
    algorithm: Algorithm
    risk: QuantumRisk
    algorithm_risk_score: float = Field(ge=0.0, le=10.0, default=0.0)
    migration_risk_score: float = Field(ge=0.0, le=10.0, default=0.0)
    severity_score: float = Field(ge=0.0, le=10.0, default=0.0)
    location: CodeLocation
    usage_type: str
    library: str | None = None
    explanation: str
    recommendation: str
    blast_radius: int = 0
    dependency_node_id: str | None = None
    migration_status: MigrationStatus = MigrationStatus.PENDING
    metadata: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Migration & Validation models
# ---------------------------------------------------------------------------


class MigrationPlan(BaseModel):
    finding_id: str
    strategy: str
    target_algorithm: Algorithm
    description: str
    estimated_complexity: str
    requires_dependency_update: bool = False
    new_dependencies: list[str] = Field(default_factory=list)
    transformation_hints: dict[str, Any] = Field(default_factory=dict)
    affected_dependency_node_ids: list[str] = Field(default_factory=list)


class TransformationResult(BaseModel):
    finding_id: str
    success: bool
    original_snippet: str | None = None
    transformed_snippet: str | None = None
    files_modified: list[Path] = Field(default_factory=list)
    error_message: str | None = None


class ValidationResult(BaseModel):
    passed: bool
    build_ok: bool | None = None
    tests_ok: bool | None = None
    test_summary: str | None = None
    regressions: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    error_output: str | None = None


# ---------------------------------------------------------------------------
# Orchestration & Session models
# ---------------------------------------------------------------------------


class MigrationSessionState(BaseModel):
    session_id: str
    target_path: Path
    findings: list[CryptoFinding] = Field(default_factory=list)
    selected_finding_ids: list[str] = Field(default_factory=list)
    current_finding_id: str | None = None
    current_attempt: int = 0
    max_attempts: int = 3
    migration_plans: list[MigrationPlan] = Field(default_factory=list)
    transformation_results: list[TransformationResult] = Field(default_factory=list)
    validation_results: list[ValidationResult] = Field(default_factory=list)
    retry_hints: str | None = None
    is_dry_run: bool = False


# ---------------------------------------------------------------------------
# Reporting models
# ---------------------------------------------------------------------------


class ScanReport(BaseModel):
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
    dependency_graph: DependencyGraph | None = None
