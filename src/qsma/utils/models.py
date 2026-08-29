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
    PENDING     = "pending"
    SELECTED    = "selected"
    IN_PROGRESS = "in_progress"
    COMPLETED   = "completed"
    FAILED      = "failed"
    SKIPPED     = "skipped"


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


# ---------------------------------------------------------------------------
# Dependency graph models  (produced by Detector, stored in Neo4j)
# ---------------------------------------------------------------------------

class DependencyNode(BaseModel):
    """
    A single node in the intra-codebase dependency graph.

    Represents one module/file in the codebase.  Edges in Neo4j express
    IMPORTS_FROM and CALLS relationships between nodes.

    Produced by: Detector (dependency graph phase)
    Consumed by: Classifier (blast-radius scoring), Planner (migration context)
    """
    node_id: str                        # Stable key: absolute file path (normalised)
    module_name: str                    # Python dotted name or language equivalent
    file: Path
    language: str                       # "python", "java", "go", "c", "rust"
    # True if this node contains ≥1 CryptoHit — marks it as a crypto-bearing module
    has_crypto: bool = False
    # Direct dependents: modules that import / call this module
    direct_dependents: list[str] = Field(default_factory=list)   # node_id list
    # Transitive dependents: all upstream callers (computed via graph traversal)
    transitive_dependents: list[str] = Field(default_factory=list)


class DependencyGraph(BaseModel):
    """
    Full intra-codebase dependency graph produced by the Detector for a
    single scan target.

    Storage: persisted to Neo4j (`neo4j://...`) keyed by session_id.
    The in-memory representation here is used for immediate blast-radius
    calculations inside the Classifier; Neo4j is the durable store for
    the Planner agent to query when reasoning about migration order.

    Produced by: Detector
    Consumed by: Classifier (blast-radius), Planner (migration sequencing)
    """
    session_id: str
    nodes: dict[str, DependencyNode] = Field(default_factory=dict)  # node_id → node
    # Adjacency list: node_id → list of node_ids it directly depends on (IMPORTS_FROM edges)
    edges: dict[str, list[str]] = Field(default_factory=dict)

    def blast_radius(self, node_id: str) -> int:
        """
        Return the count of modules that transitively depend on `node_id`.
        A higher number means changing this module affects more of the codebase.
        """
        node = self.nodes.get(node_id)
        if node is None:
            return 0
        return len(node.transitive_dependents)


# ---------------------------------------------------------------------------
# Detection models
# ---------------------------------------------------------------------------

class CryptoHit(BaseModel):
    """
    A raw, unclassified detection of a cryptographic usage site.

    Produced by: Detector (pattern-matching phase, before classification)
    Consumed by: Classifier
    """
    rule_id: str                        # e.g. "rsa-key-gen", "ecdh-exchange"
    algorithm_hint: str                 # Raw string hint from the detection rule
    usage_type: str                     # e.g. "key_exchange", "signature", "encryption"
    location: CodeLocation
    raw_node_info: dict[str, Any] = Field(default_factory=dict)
    # node_id of the DependencyNode this hit belongs to (links hit → graph)
    dependency_node_id: str | None = None


# ---------------------------------------------------------------------------
# Classification models
# ---------------------------------------------------------------------------

class CryptoFinding(BaseModel):
    """
    A classified cryptographic usage site with dual risk scores.

    The two risk dimensions are intentionally independent:
      - algorithm_risk: deterministic, NIST-table-driven — how quantum-vulnerable
        the algorithm itself is.  Hard-coded, reproducible, never calls LLM.
      - migration_risk: probabilistic, LLM-assisted — how hard/risky it will be
        to actually migrate this specific call site, accounting for blast radius
        (transitive dependent count), usage complexity, and library coupling.
        LLM call is optional; falls back to a heuristic score if LLM unavailable.

    Produced by: Classifier
    Consumed by: Planner, Reporter, Migrator
    """
    id: str                             # Stable unique ID, e.g. "QSMA-0001"
    algorithm: Algorithm
    risk: QuantumRisk                   # Derived from algorithm_risk (backward-compat alias)

    # ── Dual risk scores ─────────────────────────────────────────────────
    # Score 1: algorithm volatility — how quantum-vulnerable is this algorithm?
    # Source: hard-coded NIST risk table in Classifier.  Range 0.0–10.0.
    # 10.0 = broken by Shor's (RSA, ECC, DH); 0.0 = quantum-safe.
    algorithm_risk_score: float = Field(ge=0.0, le=10.0, default=0.0)

    # Score 2: migration complexity risk — how hard will migration actually be?
    # Source: LLM-assisted heuristic in Classifier, informed by blast_radius,
    # usage_type, library coupling, and code complexity.  Range 0.0–10.0.
    # 10.0 = extremely risky to migrate (many dependents, tightly coupled).
    # Falls back to a rule-based heuristic if LLM is unavailable.
    migration_risk_score: float = Field(ge=0.0, le=10.0, default=0.0)

    # Combined severity for display / prioritisation (weighted average or max)
    severity_score: float = Field(ge=0.0, le=10.0, default=0.0)

    location: CodeLocation
    usage_type: str                     # e.g. "key_exchange", "signature", "encryption"
    library: str | None = None          # e.g. "cryptography", "OpenSSL", "hashlib"
    explanation: str                    # Human-readable reason for the risk
    recommendation: str                 # Suggested replacement

    # ── Blast-radius context ──────────────────────────────────────────────
    # Count of modules that transitively depend on the module containing this finding.
    # Populated by Classifier from DependencyGraph.blast_radius(node_id).
    blast_radius: int = 0
    dependency_node_id: str | None = None  # Links back to DependencyGraph node

    migration_status: MigrationStatus = MigrationStatus.PENDING
    metadata: dict[str, Any] = Field(default_factory=dict)


class MigrationPlan(BaseModel):
    """
    A migration plan for a single finding.
    Produced by: Planner
    Consumed by: Migrator
    """
    finding_id: str
    strategy: str                       # e.g. "llm_assisted", "manual_only"
    target_algorithm: Algorithm
    description: str
    estimated_complexity: str           # "low" | "medium" | "high"
    requires_dependency_update: bool = False
    new_dependencies: list[str] = Field(default_factory=list)
    transformation_hints: dict[str, Any] = Field(default_factory=dict)
    # Dependency graph context passed to the Planner agent so it can reason
    # about migration order and downstream impact
    affected_dependency_node_ids: list[str] = Field(default_factory=list)


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
    # Dependency graph summary for display in the scan report
    dependency_graph: DependencyGraph | None = None


# ---------------------------------------------------------------------------
# Agent session state  (LangGraph state persisted to Redis)
# ---------------------------------------------------------------------------

class MigrationSessionState(BaseModel):
    """
    Shared state threaded through the LangGraph agent graph
    (planner_node → migrator_node → validator_node).

    Persisted to Redis after every node transition so the session can be
    resumed with `qsma migrate --resume <session_id>`.

    Produced/consumed by: Planner, Migrator, Validator
    Persisted by: utils/session.py (Redis, TTL 24 h)
    """
    session_id: str
    target_path: Path

    # ── Input findings ────────────────────────────────────────────────────
    # Full list of findings selected by the user (or --auto) for migration.
    selected_findings: list[CryptoFinding] = Field(default_factory=list)

    # ── Planner outputs ───────────────────────────────────────────────────
    # Plans produced so far; keyed by finding_id for easy lookup.
    # Appended by planner_node; read by migrator_node.
    pending_plans: dict[str, MigrationPlan] = Field(default_factory=dict)

    # ── Migrator / Validator tracking ────────────────────────────────────
    completed_findings: list[str] = Field(default_factory=list)    # finding_id list
    failed_findings: list[str] = Field(default_factory=list)       # finding_id list

    # Current finding being processed (one at a time through the loop)
    current_finding_id: str | None = None
    retry_count: int = 0                    # attempts for current finding
    retry_hints: dict[str, Any] = Field(default_factory=dict)      # from Validator

    # Accumulated transformation results
    transformation_results: list[TransformationResult] = Field(default_factory=list)

    # ── Control ───────────────────────────────────────────────────────────
    dry_run: bool = False                   # True → diff only, no file writes
    # Routing signal set by validator_node: "pass" | "retry" | "escalate" | "done"
    routing_signal: str = "pass"
