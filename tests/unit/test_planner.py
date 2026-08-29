"""
Unit tests for qsma.planner.

Uses LLMClient(provider="mock") so no real credentials are needed.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from qsma.llm.client import LLMClient
from qsma.planner import _build_plan_for_finding, planner_node, run_planner
from qsma.utils.models import (
    Algorithm,
    CodeLocation,
    CryptoFinding,
    MigrationPlan,
    MigrationSessionState,
    MigrationStatus,
    QuantumRisk,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def make_finding(
    id: str = "QSMA-0001",
    algorithm: Algorithm = Algorithm.RSA,
    usage_type: str = "signature",
    snippet: str = "key = rsa.generate_private_key(65537, 2048)",
    language: str = "python",
) -> CryptoFinding:
    return CryptoFinding(
        id=id,
        algorithm=algorithm,
        risk=QuantumRisk.CRITICAL,
        algorithm_risk_score=10.0,
        migration_risk_score=7.0,
        severity_score=8.8,
        location=CodeLocation(
            file=Path("src/crypto_utils.py"),
            line_start=5,
            line_end=7,
            snippet=snippet,
        ),
        usage_type=usage_type,
        library="cryptography",
        explanation="RSA is broken by Shor's algorithm.",
        recommendation="Migrate to ML-DSA (Dilithium).",
        metadata={"language": language},
    )


MOCK_PLAN_JSON = json.dumps({
    "strategy": "llm_assisted",
    "target_algorithm": "ML-DSA (Dilithium)",
    "description": "Replace RSA signing with ML-DSA (Dilithium) per FIPS 204.",
    "estimated_complexity": "medium",
    "requires_dependency_update": True,
    "new_dependencies": ["pqcrypto"],
    "transformation_hints": {
        "replace_import": "from cryptography.hazmat.primitives.asymmetric import rsa → import pqcrypto.sign.dilithium3 as dilithium",
        "key_size": "Dilithium3 (NIST security level 3)",
        "api_note": "generate_keys() replaces rsa.generate_private_key()",
        "caveat": "",
    },
})


# ---------------------------------------------------------------------------
# _build_plan_for_finding
# ---------------------------------------------------------------------------

class TestBuildPlanForFinding:

    def test_non_python_returns_manual_only(self):
        finding = make_finding(language="java")
        llm = LLMClient(provider="mock")
        plan = _build_plan_for_finding(finding, llm, "system prompt")
        assert plan.strategy == "manual_only"
        assert plan.finding_id == finding.id

    def test_python_rsa_calls_llm_and_parses(self):
        finding = make_finding(language="python")
        llm = MagicMock(spec=LLMClient)
        llm.chat.return_value = MOCK_PLAN_JSON

        plan = _build_plan_for_finding(finding, llm, "system prompt")

        assert plan.strategy == "llm_assisted"
        assert plan.target_algorithm == Algorithm.DILITHIUM
        assert plan.estimated_complexity == "medium"
        assert plan.requires_dependency_update is True
        assert "pqcrypto" in plan.new_dependencies
        llm.chat.assert_called_once()

    def test_llm_json_decode_error_falls_back_to_manual(self):
        finding = make_finding()
        llm = MagicMock(spec=LLMClient)
        llm.chat.return_value = "not valid json {{{"

        plan = _build_plan_for_finding(finding, llm, "system prompt")

        assert plan.strategy == "manual_only"
        assert "LLM call failed" in plan.description

    def test_llm_error_falls_back_to_manual(self):
        from qsma.llm.client import LLMError

        finding = make_finding()
        llm = MagicMock(spec=LLMClient)
        llm.chat.side_effect = LLMError("timeout")

        plan = _build_plan_for_finding(finding, llm, "system prompt")

        assert plan.strategy == "manual_only"

    def test_unknown_target_algorithm_falls_back_gracefully(self):
        finding = make_finding()
        llm = MagicMock(spec=LLMClient)
        bad_response = json.dumps({
            "strategy": "llm_assisted",
            "target_algorithm": "NOT_A_REAL_ALGORITHM",
            "description": "test",
            "estimated_complexity": "low",
            "requires_dependency_update": False,
            "new_dependencies": [],
            "transformation_hints": {},
        })
        llm.chat.return_value = bad_response

        plan = _build_plan_for_finding(finding, llm, "system prompt")
        # Should fall back to NIST table for RSA → DILITHIUM
        assert plan.target_algorithm == Algorithm.DILITHIUM


# ---------------------------------------------------------------------------
# planner_node
# ---------------------------------------------------------------------------

class TestPlannerNode:

    def test_planner_node_populates_pending_plans(self):
        finding = make_finding()
        state = MigrationSessionState(
            session_id="test-session",
            target_path=Path("/tmp/project"),
            selected_findings=[finding],
        )
        with patch("qsma.planner.LLMClient") as MockLLM:
            instance = MockLLM.return_value
            instance.chat.return_value = MOCK_PLAN_JSON
            result = planner_node(state)

        assert finding.id in result.pending_plans
        assert result.pending_plans[finding.id].strategy == "llm_assisted"

    def test_planner_node_skips_already_planned(self):
        finding = make_finding()
        existing_plan = MigrationPlan(
            finding_id=finding.id,
            strategy="manual_only",
            target_algorithm=Algorithm.UNKNOWN,
            description="already planned",
            estimated_complexity="low",
        )
        state = MigrationSessionState(
            session_id="test-session",
            target_path=Path("/tmp/project"),
            selected_findings=[finding],
            pending_plans={finding.id: existing_plan},
        )
        with patch("qsma.planner.LLMClient") as MockLLM:
            planner_node(state)
            MockLLM.return_value.chat.assert_not_called()

    def test_finding_status_set_to_selected(self):
        finding = make_finding()
        state = MigrationSessionState(
            session_id="s",
            target_path=Path("/tmp"),
            selected_findings=[finding],
        )
        with patch("qsma.planner.LLMClient") as MockLLM:
            MockLLM.return_value.chat.return_value = MOCK_PLAN_JSON
            result = planner_node(state)

        assert result.selected_findings[0].migration_status == MigrationStatus.SELECTED


# ---------------------------------------------------------------------------
# run_planner (convenience entry point)
# ---------------------------------------------------------------------------

class TestRunPlanner:

    def test_run_planner_returns_session_with_plans(self):
        findings = [make_finding("QSMA-0001"), make_finding("QSMA-0002", algorithm=Algorithm.ECDH)]
        llm = MagicMock(spec=LLMClient)
        llm.chat.return_value = MOCK_PLAN_JSON

        state = run_planner(
            findings=findings,
            session_id="s1",
            target_path=Path("/tmp"),
            llm=llm,
        )

        assert len(state.pending_plans) == 2
        assert "QSMA-0001" in state.pending_plans
        assert "QSMA-0002" in state.pending_plans
        assert state.dry_run is False

    def test_run_planner_dry_run_flag(self):
        findings = [make_finding()]
        llm = MagicMock(spec=LLMClient)
        llm.chat.return_value = MOCK_PLAN_JSON

        state = run_planner(findings, "s2", Path("/tmp"), dry_run=True, llm=llm)
        assert state.dry_run is True
