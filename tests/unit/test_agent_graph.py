"""
Unit tests for qsma.agent.graph — the LangGraph StateGraph wiring
planner_node -> migrator_node -> validator_node.

All tests force LLM_PROVIDER=mock so no network calls happen anywhere in the
chain (planner_node, migrator_node's call_llm_transform, and validator_node's
generate_retry_hints all instantiate a fresh LLMClient() internally).

Covers:
  - Happy path: valid transform -> dry-run validation passes -> routing "done"
  - Invalid transform (default mock response isn't valid Python) -> patch's
    syntax check fails -> migrator escalates -> advance -> routing "done"
    (validator never runs, since it only runs after a successful patch)
  - No findings selected -> planner runs, migrator finds nothing pending ->
    immediate "done"
  - Multiple findings are all processed in order before finishing
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from qsma.agent.graph import run_migration_session
from qsma.utils.models import Algorithm, CodeLocation, CryptoFinding, QuantumRisk


@pytest.fixture(autouse=True)
def mock_llm_provider(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "mock")


def make_finding(tmp_path: Path, id: str = "QSMA-0001", line: int = 2) -> CryptoFinding:
    file_path = tmp_path / "crypto.py"
    if not file_path.exists():
        file_path.write_text("import os\nkey = None\nprint(key)\n")
    return CryptoFinding(
        id=id,
        algorithm=Algorithm.RSA,
        risk=QuantumRisk.CRITICAL,
        algorithm_risk_score=10.0,
        migration_risk_score=5.0,
        severity_score=8.0,
        location=CodeLocation(file=file_path, line_start=line, line_end=line, snippet="key = None"),
        usage_type="key_generation",
        explanation="RSA usage detected.",
        recommendation="Migrate to ML-KEM (Kyber).",
    )


def test_happy_path_completes_with_passing_validation(tmp_path):
    finding = make_finding(tmp_path)

    with patch("qsma.migrator.call_llm_transform", return_value=(True, "key = 42\n")):
        final_state = run_migration_session(
            session_id="sess-happy",
            target_path=tmp_path,
            selected_findings=[finding],
            dry_run=True,
        )

    assert final_state.routing_signal == "done"
    assert len(final_state.transformation_results) == 1
    assert final_state.transformation_results[0].success is True
    assert len(final_state.validation_results) == 1
    assert final_state.validation_results[0].passed is True


def test_invalid_transform_escalates_without_validating(tmp_path):
    finding = make_finding(tmp_path)

    # Force a syntactically invalid replacement so patcher.apply_patch's
    # syntax check fails and migrator_node escalates.
    with patch("qsma.migrator.call_llm_transform", return_value=(True, "def broken(:\n")):
        final_state = run_migration_session(
            session_id="sess-escalate",
            target_path=tmp_path,
            selected_findings=[finding],
            dry_run=True,
        )

    assert final_state.routing_signal == "done"
    assert len(final_state.transformation_results) == 1
    assert final_state.transformation_results[0].success is False
    assert final_state.validation_results == []


def test_no_findings_finishes_immediately(tmp_path):
    final_state = run_migration_session(
        session_id="sess-empty",
        target_path=tmp_path,
        selected_findings=[],
        dry_run=True,
    )

    assert final_state.routing_signal == "done"
    assert final_state.transformation_results == []
    assert final_state.validation_results == []


def test_multiple_findings_all_processed(tmp_path):
    f1 = make_finding(tmp_path, id="QSMA-0001", line=2)
    f2 = make_finding(tmp_path, id="QSMA-0002", line=2)

    final_state = run_migration_session(
        session_id="sess-multi",
        target_path=tmp_path,
        selected_findings=[f1, f2],
        dry_run=True,
    )

    assert final_state.routing_signal == "done"
    assert len(final_state.transformation_results) == 2
    assert {tr.finding_id for tr in final_state.transformation_results} == {
        "QSMA-0001",
        "QSMA-0002",
    }
