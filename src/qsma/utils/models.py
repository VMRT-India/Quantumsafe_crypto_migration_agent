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


# ---------------------------------------------------------------------------
# Planner execution plan models
# ---------------------------------------------------------------------------

class FindingMeta(BaseModel):
    """
    Location and dependency metadata for one finding, as emitted by the Planner
    in the execution plan.  Gives the Migrator everything it needs to locate and
    transform the finding without re-reading the full CryptoFinding.

    Produced by: Planner  (inside MigrationExecutionPlan)
    Consumed by: Migrator

    Notes on location fields:
      line_start / line_end — reference coordinates from the original scan.
        They are ADVISORY ONLY.  After earlier findings in the same file are
        patched, line numbers shift.  The Migrator must locate the target by
        symbol_name / snippet context, not by relying on exact line numbers.
      symbol_name — the enclosing function, method, or class block that contains
        the crypto usage (e.g. "sign_data", "KeyManager.__init__").  Empty string
        if the Detector could not determine it.  Primary locator for the Migrator.
    """
    finding_id: str
    order: int                          # global sequence number (1-based) across all waves
    file: Path
    language: str                       # e.g. "python", "java", "go"
    symbol_name: str = ""               # enclosing function/class/block name; "" if unknown
    line_start: int
    line_end: int
    algorithm: str                      # source algorithm value string
    description: str                    # human-readable summary of what to change
    # finding_ids of OTHER findings whose migrations must complete before this one
    depends_on: list[str] = Field(default_factory=list)


class MigrationExecutionPlan(BaseModel):
    """
    The full output document produced by the Planner stage.
    This is the direct input to the Migrator stage.

    Structure:
      waves      — parallel execution batches in dependency order.
                   wave[0] can all run in parallel (no inter-dependencies).
                   wave[1] can start only when ALL of wave[0] are complete.
                   etc.  Max 6 findings per wave (parallel agent cap).
      finding_plans — the MigrationPlan for each finding_id
      finding_meta  — location + dependency metadata for each finding_id

    Produced by: Planner
    Consumed by: Migrator
    Persisted to: Redis session (keyed by session_id)
    """
    session_id: str
    waves: list[list[str]] = Field(default_factory=list)
    # finding_id → MigrationPlan (what to change and how)
    finding_plans: dict[str, MigrationPlan] = Field(default_factory=dict)
    # finding_id → FindingMeta (where to change it)
    finding_meta: dict[str, FindingMeta] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Graph envelope — thin session state for LangGraph wiring only
# ---------------------------------------------------------------------------

class MigrationSessionState(BaseModel):
    """
    Thin envelope threaded through the LangGraph graph by agent/graph.py.

    This model holds ONLY the data that must cross module boundaries between
    the three pipeline stages.  Each stage owns its own internal state type:
      Planner  → PlannerState   (qsma/planner/state.py)
      Migrator → MigratorState  (qsma/migrator/state.py)
      Validator→ ValidatorState (qsma/validator/state.py)

    graph.py reads the appropriate sub-state from here before calling each
    node and writes the node's output back when it completes.

    Persisted to Redis after each node transition (TTL 24 h, ADR-008).
    Resume via `qsma migrate --resume <session_id>`.
    """
    session_id: str
    target_path: Path

    # ── Cross-boundary outputs (written by each stage, read by the next) ─
    execution_plan: MigrationExecutionPlan | None = None     # Planner → Migrator
    transformation_results: list[TransformationResult] = Field(default_factory=list)  # Migrator → Validator
    validation_results: list[ValidationResult] = Field(default_factory=list)          # Validator → Reporter

    # ── Routing (set by each node for graph.py to act on) ─────────────────
    current_finding_id: str | None = None
    routing_signal: str = "pass"    # "validate" | "retry" | "escalate" | "done"
