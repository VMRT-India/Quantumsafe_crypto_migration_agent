"""
qsma.classifier
================
Public API for the Classifier module.

Consumes the Detector's output (list[CryptoHit] + DependencyGraph) and produces
list[CryptoFinding] — the dual-risk-scored objects the user selects from before
migration (see qsma.planner / qsma.agent.graph).

Scoring model (ARCHITECTURE.md, ADR-011)
-----------------------------------------
Score 1 — algorithm_risk_score (deterministic, never calls an LLM):
    A hard-coded NIST-aligned table keyed by Algorithm. Classical
    asymmetric primitives broken outright by Shor's algorithm score highest;
    already-deprecated classical primitives (DES, MD5, SHA-1) score nearly as
    high since they are also legacy-broken; AES-128 is Grover-weakened but not
    broken; AES-256/SHA-2 are quantum-resistant enough to be low priority;
    post-quantum targets score 0.

Score 2 — migration_risk_score (LLM-assisted, heuristic fallback always available):
    Derived from blast_radius (size of the DependencyGraph transitive-dependent
    set) and usage_type (key generation / signing is harder to migrate safely
    than a bare hash call). An LLMClient may be supplied to refine the
    heuristic with reasoning; if omitted, unavailable, or the provider is
    "mock", the heuristic value is used as-is.

severity_score = 0.6 * algorithm_risk_score + 0.4 * migration_risk_score

Usage::

    from qsma.classifier import classify
    findings = classify(hits, graph)
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from qsma.utils.models import (
    Algorithm,
    CryptoFinding,
    CryptoHit,
    DependencyGraph,
    QuantumRisk,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Score 1 — algorithm_risk_score: deterministic NIST-aligned table
# ---------------------------------------------------------------------------
ALGORITHM_RISK_TABLE: dict[Algorithm, float] = {
    # Broken outright by Shor's algorithm — highest priority to migrate.
    Algorithm.RSA: 10.0,
    Algorithm.ECDSA: 10.0,
    Algorithm.ECDH: 10.0,
    Algorithm.DSA: 10.0,
    Algorithm.DH: 10.0,
    # Already classically broken/deprecated (not a PQC concern per se, but
    # still top priority — no reason to ever keep these).
    Algorithm.MD5: 9.5,
    Algorithm.SHA1: 9.0,
    Algorithm.DES: 9.0,
    Algorithm.TRIPLE_DES: 8.5,
    # Grover-weakened but not broken — halved effective key strength.
    Algorithm.AES_128: 7.0,
    # Quantum-resistant enough at current key sizes — low priority.
    Algorithm.SHA256: 3.0,
    Algorithm.SHA384: 2.5,
    Algorithm.SHA512: 2.0,
    Algorithm.AES_256: 2.0,
    # Post-quantum targets — already migrated, no risk.
    Algorithm.KYBER: 0.0,
    Algorithm.DILITHIUM: 0.0,
    Algorithm.FALCON: 0.0,
    Algorithm.SPHINCS: 0.0,
    # Unknown hint — assume medium risk until a human/LLM disambiguates.
    Algorithm.UNKNOWN: 5.0,
}

# usage_type multipliers applied to the blast-radius-derived base score —
# migrating a key-generation/signing call safely is riskier than a bare
# import or a one-shot hash call.
_USAGE_TYPE_WEIGHT: dict[str, float] = {
    "key_generation": 1.0,
    "key_exchange": 1.0,
    "signature": 0.9,
    "encryption": 0.8,
    "hashing": 0.5,
    "import": 0.3,
}
_DEFAULT_USAGE_WEIGHT = 0.6


def algorithm_from_hit(hit: CryptoHit) -> Algorithm:
    """Map a CryptoHit's free-text algorithm_hint onto the Algorithm enum."""
    raw = (hit.algorithm_hint or "").strip().upper()
    for member in Algorithm:
        if member.value.upper() == raw:
            return member
    # Loose fallback: substring match (e.g. "RSA-2048" -> RSA)
    for member in Algorithm:
        if member.value.upper() in raw or raw in member.value.upper():
            return member
    logger.debug("Unrecognized algorithm_hint %r — classifying as UNKNOWN", hit.algorithm_hint)
    return Algorithm.UNKNOWN


def _blast_radius(hit: CryptoHit, graph: DependencyGraph) -> int:
    node_id = hit.dependency_node_id
    if node_id is None:
        return 0
    node = graph.nodes.get(node_id)
    if node is None:
        return 0
    return len(node.transitive_dependents)


def _heuristic_migration_risk(hit: CryptoHit, graph: DependencyGraph) -> float:
    """Pure heuristic — no LLM. Always the fallback / default path."""
    blast_radius = _blast_radius(hit, graph)
    # Normalize blast radius into 0-10: diminishing returns past ~10 dependents.
    radius_score = min(10.0, blast_radius * 1.5)
    weight = _USAGE_TYPE_WEIGHT.get(hit.usage_type, _DEFAULT_USAGE_WEIGHT)
    return round(min(10.0, radius_score * weight), 2)


def migration_risk_score(
    hit: CryptoHit,
    graph: DependencyGraph,
    llm: Any | None = None,
) -> float:
    """
    Score 2: migration_risk_score. Heuristic by default; LLM-refined when a
    usable LLMClient is supplied (never required — see module docstring).
    """
    heuristic = _heuristic_migration_risk(hit, graph)

    if llm is None or getattr(llm, "provider", "mock") == "mock":
        return heuristic

    try:
        blast_radius = _blast_radius(hit, graph)
        prompt = (
            "Rate the migration risk of replacing this cryptographic usage on a "
            "0-10 scale (0=trivial, 10=extremely risky to change safely). "
            f"Algorithm: {hit.algorithm_hint}. Usage type: {hit.usage_type}. "
            f"Number of dependent modules (blast radius): {blast_radius}. "
            f"Heuristic estimate: {heuristic}. "
            "Reply with ONLY a single number between 0 and 10."
        )
        messages = [
            {"role": "system", "content": "You are a cautious migration risk assessor."},
            {"role": "user", "content": prompt},
        ]
        response = llm.chat(messages)
        score = float(str(response).strip().split()[0])
        return round(max(0.0, min(10.0, score)), 2)
    except Exception:
        logger.exception("LLM migration_risk_score failed — falling back to heuristic")
        return heuristic


def _read_snippet(file: Path, line_start: int, line_end: int) -> str | None:
    """
    Read the exact source lines [line_start, line_end] (1-based, inclusive)
    a CryptoHit points at. This is the only place in the pipeline that reads
    real source text for a finding — without it, Planner and Migrator only
    ever see the generic `explanation` sentence instead of actual code.
    """
    try:
        lines = file.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    if line_start < 1 or line_end < line_start or line_end > len(lines):
        return None
    return "\n".join(lines[line_start - 1 : line_end])


def _risk_bucket(severity_score: float) -> QuantumRisk:
    if severity_score >= 8.0:
        return QuantumRisk.CRITICAL
    if severity_score >= 5.5:
        return QuantumRisk.HIGH
    if severity_score >= 3.0:
        return QuantumRisk.MEDIUM
    if severity_score > 0.0:
        return QuantumRisk.LOW
    return QuantumRisk.INFO


_PQC_TARGET_HINT: dict[Algorithm, str] = {
    Algorithm.RSA: "ML-KEM (Kyber) for key exchange / ML-DSA (Dilithium) for signatures",
    Algorithm.ECDSA: "ML-DSA (Dilithium) or SLH-DSA (SPHINCS+)",
    Algorithm.ECDH: "ML-KEM (Kyber)",
    Algorithm.DSA: "ML-DSA (Dilithium)",
    Algorithm.DH: "ML-KEM (Kyber)",
    Algorithm.MD5: "SHA-256 or SHA-3 (not a PQC concern — legacy-broken hash)",
    Algorithm.SHA1: "SHA-256 or SHA-3 (not a PQC concern — legacy-broken hash)",
    Algorithm.DES: "AES-256",
    Algorithm.TRIPLE_DES: "AES-256",
    Algorithm.AES_128: "AES-256",
}


def _explanation_and_recommendation(algorithm: Algorithm, hit: CryptoHit) -> tuple[str, str]:
    explanation = (
        f"{algorithm.value} usage detected ({hit.usage_type}) at "
        f"{hit.location.file}:{hit.location.line_start}."
    )
    target = _PQC_TARGET_HINT.get(algorithm)
    if target:
        recommendation = f"Migrate to {target}."
    elif algorithm in (Algorithm.SHA256, Algorithm.SHA384, Algorithm.SHA512, Algorithm.AES_256):
        recommendation = "Already quantum-resistant at this key/output size — no action required."
    elif algorithm == Algorithm.UNKNOWN:
        recommendation = "Manually review — algorithm could not be determined automatically."
    else:
        recommendation = "Already a post-quantum algorithm — no action required."
    return explanation, recommendation


def classify(
    hits: list[CryptoHit],
    graph: DependencyGraph,
    llm: Any | None = None,
) -> list[CryptoFinding]:
    """
    Score every CryptoHit and produce the ordered list[CryptoFinding] the rest
    of the pipeline (Planner, Reporter, CLI) consumes.

    Parameters
    ----------
    hits:
        Output of qsma.detector.detect() (Phase A).
    graph:
        Output of qsma.detector.detect() (Phase B) — used for blast_radius.
    llm:
        Optional LLMClient to refine migration_risk_score. Omit for the pure
        deterministic + heuristic path (no network calls).
    """
    findings: list[CryptoFinding] = []
    for i, hit in enumerate(hits, start=1):
        algorithm = algorithm_from_hit(hit)
        alg_score = ALGORITHM_RISK_TABLE.get(algorithm, 5.0)
        mig_score = migration_risk_score(hit, graph, llm)
        severity = round(0.6 * alg_score + 0.4 * mig_score, 2)
        explanation, recommendation = _explanation_and_recommendation(algorithm, hit)
        snippet = _read_snippet(
            hit.location.file, hit.location.line_start, hit.location.line_end
        )
        location = (
            hit.location.model_copy(update={"snippet": snippet}) if snippet else hit.location
        )

        findings.append(
            CryptoFinding(
                id=f"QSMA-{i:04d}",
                algorithm=algorithm,
                risk=_risk_bucket(severity),
                algorithm_risk_score=alg_score,
                migration_risk_score=mig_score,
                severity_score=severity,
                location=location,
                usage_type=hit.usage_type,
                library=hit.raw_node_info.get("module") or hit.raw_node_info.get("qualified_name"),
                explanation=explanation,
                recommendation=recommendation,
                blast_radius=_blast_radius(hit, graph),
                dependency_node_id=hit.dependency_node_id,
                metadata={"rule_id": hit.rule_id},
            )
        )

    # Deterministic, highest-severity-first ordering.
    findings.sort(key=lambda f: f.severity_score, reverse=True)
    return findings


__all__ = [
    "ALGORITHM_RISK_TABLE",
    "algorithm_from_hit",
    "migration_risk_score",
    "classify",
]
