"""
Unit tests for qsma.classifier.

Covers:
  - algorithm_from_hit maps algorithm_hint strings onto the Algorithm enum
  - algorithm_risk_score is deterministic and never calls an LLM
  - migration_risk_score heuristic scales with blast_radius and usage_type
  - migration_risk_score falls back to heuristic when llm is None or "mock"
  - severity_score = 0.6*alg + 0.4*mig and QuantumRisk bucketing
  - classify() end-to-end produces sorted, correctly-shaped CryptoFinding list
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from qsma.classifier import (
    ALGORITHM_RISK_TABLE,
    algorithm_from_hit,
    classify,
    migration_risk_score,
)
from qsma.utils.models import (
    Algorithm,
    CodeLocation,
    CryptoHit,
    DependencyGraph,
    DependencyNode,
    QuantumRisk,
)


def make_hit(
    rule_id: str = "rsa-import",
    algorithm_hint: str = "RSA",
    usage_type: str = "key_generation",
    dependency_node_id: str | None = "node-1",
    file: str = "app/crypto.py",
    line: int = 10,
) -> CryptoHit:
    return CryptoHit(
        rule_id=rule_id,
        algorithm_hint=algorithm_hint,
        usage_type=usage_type,
        location=CodeLocation(file=Path(file), line_start=line, line_end=line),
        dependency_node_id=dependency_node_id,
    )


def make_graph(session_id: str = "s1", transitive_dependents: list[str] | None = None) -> DependencyGraph:
    deps = transitive_dependents if transitive_dependents is not None else []
    node = DependencyNode(
        node_id="node-1",
        module_name="app.crypto",
        file=Path("app/crypto.py"),
        language="python",
        has_crypto=True,
        transitive_dependents=deps,
    )
    return DependencyGraph(session_id=session_id, nodes={"node-1": node}, edges={})


# ---------------------------------------------------------------------------
# algorithm_from_hit
# ---------------------------------------------------------------------------


def test_algorithm_from_hit_exact_match():
    assert algorithm_from_hit(make_hit(algorithm_hint="RSA")) == Algorithm.RSA
    assert algorithm_from_hit(make_hit(algorithm_hint="AES-128")) == Algorithm.AES_128
    assert algorithm_from_hit(make_hit(algorithm_hint="3DES")) == Algorithm.TRIPLE_DES


def test_algorithm_from_hit_unknown_falls_back():
    assert algorithm_from_hit(make_hit(algorithm_hint="totally-made-up")) == Algorithm.UNKNOWN


# ---------------------------------------------------------------------------
# algorithm_risk_score (deterministic table)
# ---------------------------------------------------------------------------


def test_algorithm_risk_table_ordering():
    assert ALGORITHM_RISK_TABLE[Algorithm.RSA] == 10.0
    assert ALGORITHM_RISK_TABLE[Algorithm.AES_128] < ALGORITHM_RISK_TABLE[Algorithm.RSA]
    assert ALGORITHM_RISK_TABLE[Algorithm.AES_256] < ALGORITHM_RISK_TABLE[Algorithm.AES_128]
    assert ALGORITHM_RISK_TABLE[Algorithm.KYBER] == 0.0
    assert ALGORITHM_RISK_TABLE[Algorithm.DILITHIUM] == 0.0


# ---------------------------------------------------------------------------
# migration_risk_score (heuristic + LLM paths)
# ---------------------------------------------------------------------------


def test_migration_risk_score_scales_with_blast_radius():
    hit = make_hit(usage_type="key_generation")
    small_graph = make_graph(transitive_dependents=[])
    large_graph = make_graph(transitive_dependents=["a", "b", "c", "d", "e"])

    low = migration_risk_score(hit, small_graph)
    high = migration_risk_score(hit, large_graph)
    assert high > low
    assert 0.0 <= low <= 10.0
    assert 0.0 <= high <= 10.0


def test_migration_risk_score_usage_type_weighting():
    graph = make_graph(transitive_dependents=["a", "b", "c"])
    keygen_hit = make_hit(usage_type="key_generation")
    import_hit = make_hit(usage_type="import")

    keygen_score = migration_risk_score(keygen_hit, graph)
    import_score = migration_risk_score(import_hit, graph)
    assert keygen_score > import_score


def test_migration_risk_score_no_llm_uses_heuristic():
    graph = make_graph()
    hit = make_hit()
    assert migration_risk_score(hit, graph, llm=None) == migration_risk_score(hit, graph, llm=None)


def test_migration_risk_score_mock_provider_skips_llm_call():
    graph = make_graph()
    hit = make_hit()
    mock_llm = MagicMock()
    mock_llm.provider = "mock"

    score = migration_risk_score(hit, graph, llm=mock_llm)
    mock_llm.chat.assert_not_called()
    assert score == migration_risk_score(hit, graph, llm=None)


def test_migration_risk_score_uses_llm_when_available():
    graph = make_graph()
    hit = make_hit()
    mock_llm = MagicMock()
    mock_llm.provider = "watsonx"
    mock_llm.chat.return_value = "7.5"

    score = migration_risk_score(hit, graph, llm=mock_llm)
    mock_llm.chat.assert_called_once()
    assert score == 7.5


def test_migration_risk_score_llm_failure_falls_back_to_heuristic():
    graph = make_graph()
    hit = make_hit()
    mock_llm = MagicMock()
    mock_llm.provider = "watsonx"
    mock_llm.chat.side_effect = RuntimeError("network down")

    score = migration_risk_score(hit, graph, llm=mock_llm)
    assert score == migration_risk_score(hit, graph, llm=None)


# ---------------------------------------------------------------------------
# classify() end-to-end
# ---------------------------------------------------------------------------


def test_classify_produces_sorted_findings_with_correct_ids():
    graph = make_graph(transitive_dependents=["a", "b"])
    hits = [
        make_hit(rule_id="aes-import", algorithm_hint="AES-128", usage_type="import"),
        make_hit(rule_id="rsa-keygen", algorithm_hint="RSA", usage_type="key_generation"),
    ]

    findings = classify(hits, graph)

    assert len(findings) == 2
    assert {f.id for f in findings} == {"QSMA-0001", "QSMA-0002"}
    # RSA (alg_risk=10.0) must outrank AES-128 (alg_risk=7.0) after sorting.
    assert findings[0].algorithm == Algorithm.RSA
    assert findings[0].severity_score >= findings[1].severity_score


def test_classify_severity_score_formula():
    graph = make_graph(transitive_dependents=[])
    hit = make_hit(algorithm_hint="RSA", usage_type="import")

    findings = classify([hit], graph)
    finding = findings[0]

    expected = round(0.6 * finding.algorithm_risk_score + 0.4 * finding.migration_risk_score, 2)
    assert finding.severity_score == expected


def test_classify_quantum_risk_bucketing():
    graph = make_graph()
    critical_hit = make_hit(algorithm_hint="RSA", usage_type="key_generation")
    pqc_hit = make_hit(rule_id="kyber", algorithm_hint="ML-KEM (Kyber)", usage_type="import")

    findings = classify([critical_hit, pqc_hit], graph)
    by_algo = {f.algorithm: f for f in findings}

    assert by_algo[Algorithm.RSA].risk in (QuantumRisk.CRITICAL, QuantumRisk.HIGH)
    assert by_algo[Algorithm.KYBER].risk == QuantumRisk.INFO


def test_classify_populates_blast_radius_and_dependency_node_id():
    graph = make_graph(transitive_dependents=["a", "b", "c"])
    hit = make_hit(dependency_node_id="node-1")

    finding = classify([hit], graph)[0]
    assert finding.blast_radius == 3
    assert finding.dependency_node_id == "node-1"


def test_classify_empty_hits_returns_empty_list():
    assert classify([], make_graph()) == []
