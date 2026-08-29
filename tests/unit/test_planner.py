"""
Unit tests for qsma.planner.

Covers:
  - All languages trigger LLM call (no language gate)
  - Topological sort: dependency order respected
  - Parallel wave packing: independent findings grouped, capped at max_parallel
  - source_algorithm always injected into transformation_hints
  - LLM failure falls back to manual_only (any language)
  - Resume path: planner_node skips if execution_plan already set
  - run_planner convenience entry point
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from qsma.llm.client import LLMClient, LLMError
from qsma.planner import (
    _build_plan_for_finding,
    _build_waves,
    _topo_sort_findings,
    planner_node,
    run_planner,
)
from qsma.planner.state import PlannerState
from qsma.utils.models import (
    Algorithm,
    CodeLocation,
    CryptoFinding,
    MigrationExecutionPlan,
    MigrationPlan,
    MigrationStatus,
    QuantumRisk,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_finding(
    id: str,
    algorithm: Algorithm = Algorithm.RSA,
    blast_radius: int = 0,
    language: str = "python",
    snippet: str = "key = rsa.generate_private_key(65537, 2048)",
    dependency_node_id: str | None = None,
    depends_on_node_ids: list[str] | None = None,
    line_start: int = 1,
    line_end: int = 3,
) -> CryptoFinding:
    meta: dict = {"language": language}
    if depends_on_node_ids:
        meta["depends_on_node_ids"] = depends_on_node_ids
    return CryptoFinding(
        id=id,
        algorithm=algorithm,
        risk=QuantumRisk.CRITICAL,
        algorithm_risk_score=10.0,
        migration_risk_score=7.0,
        severity_score=8.8,
        blast_radius=blast_radius,
        dependency_node_id=dependency_node_id,
        location=CodeLocation(
            file=Path("src/crypto.py"),
            line_start=line_start,
            line_end=line_end,
            snippet=snippet,
        ),
        usage_type="signature",
        library="cryptography",
        explanation="RSA is quantum-vulnerable.",
        recommendation="Use ML-DSA.",
        metadata=meta,
    )


MOCK_PLAN_JSON = json.dumps({
    "strategy": "llm_assisted",
    "target_algorithm": "ML-DSA (Dilithium)",
    "description": "Replace RSA with ML-DSA (Dilithium) per FIPS 204.",
    "estimated_complexity": "medium",
    "requires_dependency_update": True,
    "new_dependencies": ["pqcrypto"],
    "transformation_hints": {
        "replace_import": "from cryptography... → import dilithium",
        "key_size": "Dilithium3",
        "api_note": "generate_keys() replaces generate_private_key()",
        "caveat": "",
    },
})


def mock_llm(response: str = MOCK_PLAN_JSON) -> MagicMock:
    llm = MagicMock(spec=LLMClient)
    llm.chat.return_value = response
    return llm


# ---------------------------------------------------------------------------
# _build_plan_for_finding — language gate removed
# ---------------------------------------------------------------------------

class TestBuildPlanForFinding:

    def test_python_finding_calls_llm(self):
        finding = make_finding("F1", language="python")
        plan = _build_plan_for_finding(finding, mock_llm(), "sys prompt")
        assert plan.strategy == "llm_assisted"
        assert plan.target_algorithm == Algorithm.DILITHIUM

    def test_java_finding_calls_llm(self):
        """No language gate — Java findings go to LLM."""
        finding = make_finding("F1", language="java")
        plan = _build_plan_for_finding(finding, mock_llm(), "sys prompt")
        assert plan.strategy == "llm_assisted"

    def test_go_finding_calls_llm(self):
        finding = make_finding("F1", language="go")
        plan = _build_plan_for_finding(finding, mock_llm(), "sys prompt")
        assert plan.strategy == "llm_assisted"

    def test_source_algorithm_always_in_hints(self):
        """Planner must inject source_algorithm regardless of LLM response."""
        finding = make_finding("F1", algorithm=Algorithm.ECDH, language="python")
        plan = _build_plan_for_finding(finding, mock_llm(), "sys prompt")
        assert plan.transformation_hints["source_algorithm"] == Algorithm.ECDH.value

    def test_source_algorithm_injected_even_when_llm_returns_empty_hints(self):
        response = json.dumps({
            "strategy": "llm_assisted",
            "target_algorithm": "ML-KEM (Kyber)",
            "description": "Replace ECDH.",
            "estimated_complexity": "medium",
            "requires_dependency_update": False,
            "new_dependencies": [],
            "transformation_hints": {},   # LLM returned empty hints
        })
        finding = make_finding("F1", algorithm=Algorithm.ECDH)
        plan = _build_plan_for_finding(finding, mock_llm(response), "sys")
        assert plan.transformation_hints["source_algorithm"] == "ECDH"

    def test_llm_json_decode_error_falls_back_to_manual_any_language(self):
        for lang in ("python", "java", "go", "rust"):
            finding = make_finding("F1", language=lang)
            llm = mock_llm("not valid json {{{")
            plan = _build_plan_for_finding(finding, llm, "sys")
            assert plan.strategy == "manual_only", f"Expected manual_only for {lang}"
            assert plan.transformation_hints["source_algorithm"] == finding.algorithm.value

    def test_llm_error_falls_back_to_manual(self):
        finding = make_finding("F1")
        llm = mock_llm()
        llm.chat.side_effect = LLMError("timeout")
        plan = _build_plan_for_finding(finding, llm, "sys")
        assert plan.strategy == "manual_only"
        assert plan.transformation_hints["source_algorithm"] == finding.algorithm.value

    def test_unknown_target_algorithm_resolves_to_unknown(self):
        response = json.dumps({
            "strategy": "llm_assisted",
            "target_algorithm": "NOT_REAL",
            "description": "test",
            "estimated_complexity": "low",
            "requires_dependency_update": False,
            "new_dependencies": [],
            "transformation_hints": {},
        })
        finding = make_finding("F1")
        plan = _build_plan_for_finding(finding, mock_llm(response), "sys")
        assert plan.target_algorithm == Algorithm.UNKNOWN

    def test_language_injected_into_prompt(self):
        """LLM should receive language in the prompt so it can produce correct code."""
        finding = make_finding("F1", language="go")
        llm = mock_llm()
        _build_plan_for_finding(finding, llm, "sys")
        call_args = llm.chat.call_args[0][0]  # messages list
        user_content = call_args[1]["content"]
        assert "Language: go" in user_content
        assert "```go" in user_content


# ---------------------------------------------------------------------------
# _topo_sort_findings
# ---------------------------------------------------------------------------

class TestTopoSort:

    def test_no_deps_sorted_by_descending_blast_radius(self):
        f1 = make_finding("F1", blast_radius=1)
        f2 = make_finding("F2", blast_radius=5)
        f3 = make_finding("F3", blast_radius=3)
        ordered = _topo_sort_findings([f1, f2, f3])
        assert [f.id for f in ordered] == ["F2", "F3", "F1"]

    def test_dependency_order_respected(self):
        """
        Graph: F2 depends on F1 (F1 must be migrated before F2).
        dependency_node_id: F1="node-1", F2="node-2"
        F2.metadata["depends_on_node_ids"] = ["node-1"]
        """
        f1 = make_finding("F1", blast_radius=2, dependency_node_id="node-1")
        f2 = make_finding("F2", blast_radius=0, dependency_node_id="node-2",
                          depends_on_node_ids=["node-1"])
        ordered = _topo_sort_findings([f2, f1])  # pass in reverse order
        ids = [f.id for f in ordered]
        assert ids.index("F1") < ids.index("F2")

    def test_chain_order(self):
        """F3 → F2 → F1: correct order is F1, F2, F3."""
        f1 = make_finding("F1", blast_radius=3, dependency_node_id="n1")
        f2 = make_finding("F2", blast_radius=1, dependency_node_id="n2",
                          depends_on_node_ids=["n1"])
        f3 = make_finding("F3", blast_radius=0, dependency_node_id="n3",
                          depends_on_node_ids=["n2"])
        ordered = _topo_sort_findings([f3, f1, f2])
        ids = [f.id for f in ordered]
        assert ids == ["F1", "F2", "F3"]

    def test_independent_findings_all_present(self):
        findings = [make_finding(f"F{i}", blast_radius=i) for i in range(5)]
        ordered = _topo_sort_findings(findings)
        assert len(ordered) == 5
        assert {f.id for f in ordered} == {f"F{i}" for i in range(5)}


# ---------------------------------------------------------------------------
# _build_waves
# ---------------------------------------------------------------------------

class TestBuildWaves:

    def test_all_independent_fits_in_one_wave(self):
        findings = [make_finding(f"F{i}") for i in range(4)]
        deps_of = {f.id: [] for f in findings}
        waves = _build_waves(findings, deps_of, max_parallel=6)
        assert len(waves) == 1
        assert set(waves[0]) == {f.id for f in findings}

    def test_wave_cap_splits_into_multiple_waves(self):
        findings = [make_finding(f"F{i}") for i in range(8)]
        deps_of = {f.id: [] for f in findings}
        waves = _build_waves(findings, deps_of, max_parallel=6)
        assert len(waves) == 2
        assert len(waves[0]) == 6
        assert len(waves[1]) == 2

    def test_dependent_finding_goes_to_next_wave(self):
        """F2 depends on F1 → F1 in wave 0, F2 in wave 1."""
        f1 = make_finding("F1")
        f2 = make_finding("F2")
        deps_of = {"F1": [], "F2": ["F1"]}
        waves = _build_waves([f1, f2], deps_of, max_parallel=6)
        assert "F1" in waves[0]
        assert "F2" in waves[1]

    def test_diamond_dependency(self):
        """
        F1
        ├─ F2 (depends on F1)
        └─ F3 (depends on F1)
           F4 (depends on F2 and F3)
        Expected: wave0=[F1], wave1=[F2,F3], wave2=[F4]
        """
        f1 = make_finding("F1")
        f2 = make_finding("F2")
        f3 = make_finding("F3")
        f4 = make_finding("F4")
        deps_of = {"F1": [], "F2": ["F1"], "F3": ["F1"], "F4": ["F2", "F3"]}
        waves = _build_waves([f1, f2, f3, f4], deps_of, max_parallel=6)
        assert "F1" in waves[0]
        f2_wave = next(i for i, w in enumerate(waves) if "F2" in w)
        f3_wave = next(i for i, w in enumerate(waves) if "F3" in w)
        f4_wave = next(i for i, w in enumerate(waves) if "F4" in w)
        assert f2_wave > 0
        assert f3_wave > 0
        assert f4_wave > f2_wave
        assert f4_wave > f3_wave


# ---------------------------------------------------------------------------
# planner_node
# ---------------------------------------------------------------------------

class TestPlannerNode:

    def test_produces_execution_plan(self):
        findings = [make_finding("F1"), make_finding("F2", algorithm=Algorithm.ECDH)]
        state = PlannerState(
            session_id="s", target_path=Path("/tmp"), selected_findings=findings
        )
        with patch("qsma.planner.LLMClient") as MockLLM:
            MockLLM.return_value.chat.return_value = MOCK_PLAN_JSON
            result = planner_node(state)

        assert result.execution_plan is not None
        assert isinstance(result.execution_plan, MigrationExecutionPlan)
        assert "F1" in result.execution_plan.finding_plans
        assert "F2" in result.execution_plan.finding_plans

    def test_finding_meta_populated(self):
        finding = make_finding("F1", language="java")
        state = PlannerState(
            session_id="s", target_path=Path("/tmp"), selected_findings=[finding]
        )
        with patch("qsma.planner.LLMClient") as MockLLM:
            MockLLM.return_value.chat.return_value = MOCK_PLAN_JSON
            result = planner_node(state)

        meta = result.execution_plan.finding_meta["F1"]
        assert meta.language == "java"
        assert meta.file == Path("src/crypto.py")
        assert meta.order == 1
        assert meta.symbol_name == ""       # not set in metadata → empty string

    def test_finding_meta_order_sequential(self):
        """Order numbers must be 1-based and sequential across all waves."""
        findings = [make_finding(f"F{i}") for i in range(4)]
        state = PlannerState(
            session_id="s", target_path=Path("/tmp"), selected_findings=findings
        )
        with patch("qsma.planner.LLMClient") as MockLLM:
            MockLLM.return_value.chat.return_value = MOCK_PLAN_JSON
            result = planner_node(state)

        orders = sorted(
            meta.order for meta in result.execution_plan.finding_meta.values()
        )
        assert orders == list(range(1, 5))

    def test_finding_meta_symbol_name_forwarded(self):
        """symbol_name from finding.metadata must be forwarded into FindingMeta."""
        finding = make_finding("F1")
        finding.metadata["symbol_name"] = "sign_data"
        state = PlannerState(
            session_id="s", target_path=Path("/tmp"), selected_findings=[finding]
        )
        with patch("qsma.planner.LLMClient") as MockLLM:
            MockLLM.return_value.chat.return_value = MOCK_PLAN_JSON
            result = planner_node(state)

        assert result.execution_plan.finding_meta["F1"].symbol_name == "sign_data"

    def test_intra_wave_sorted_by_file_then_line(self):
        """
        Two findings in the same file, independent of each other.
        The one with the lower line_start must come first inside the wave.
        """
        f_low  = make_finding("F_low",  line_start=5,  line_end=8)
        f_high = make_finding("F_high", line_start=20, line_end=22)
        # Override both to same file so sorting is deterministic
        f_low.location.file  = Path("src/same_file.py")
        f_high.location.file = Path("src/same_file.py")

        state = PlannerState(
            session_id="s", target_path=Path("/tmp"),
            selected_findings=[f_high, f_low],   # pass high-line first
        )
        with patch("qsma.planner.LLMClient") as MockLLM:
            MockLLM.return_value.chat.return_value = MOCK_PLAN_JSON
            result = planner_node(state)

        wave0 = result.execution_plan.waves[0]
        assert wave0.index("F_low") < wave0.index("F_high")
        # order numbers must reflect the sorted position
        assert result.execution_plan.finding_meta["F_low"].order < \
               result.execution_plan.finding_meta["F_high"].order

    def test_migration_order_flat_list(self):
        findings = [make_finding(f"F{i}") for i in range(3)]
        state = PlannerState(
            session_id="s", target_path=Path("/tmp"), selected_findings=findings
        )
        with patch("qsma.planner.LLMClient") as MockLLM:
            MockLLM.return_value.chat.return_value = MOCK_PLAN_JSON
            result = planner_node(state)

        assert len(result.migration_order) == 3
        assert set(result.migration_order) == {"F0", "F1", "F2"}

    def test_resume_skips_planner(self):
        """If execution_plan is already set, planner_node must not call LLM."""
        finding = make_finding("F1")
        existing_plan = MigrationExecutionPlan(
            session_id="s", waves=[["F1"]],
            finding_plans={"F1": MigrationPlan(
                finding_id="F1", strategy="llm_assisted",
                target_algorithm=Algorithm.DILITHIUM,
                description="already planned", estimated_complexity="low",
            )},
            finding_meta={},
        )
        state = PlannerState(
            session_id="s", target_path=Path("/tmp"),
            selected_findings=[finding],
            execution_plan=existing_plan,
        )
        with patch("qsma.planner.LLMClient") as MockLLM:
            planner_node(state)
            MockLLM.return_value.chat.assert_not_called()

    def test_finding_status_set_to_in_progress(self):
        finding = make_finding("F1")
        state = PlannerState(
            session_id="s", target_path=Path("/tmp"), selected_findings=[finding]
        )
        with patch("qsma.planner.LLMClient") as MockLLM:
            MockLLM.return_value.chat.return_value = MOCK_PLAN_JSON
            result = planner_node(state)

        assert result.selected_findings[0].migration_status == MigrationStatus.IN_PROGRESS

    def test_pending_plans_mirrored_from_execution_plan(self):
        finding = make_finding("F1")
        state = PlannerState(
            session_id="s", target_path=Path("/tmp"), selected_findings=[finding]
        )
        with patch("qsma.planner.LLMClient") as MockLLM:
            MockLLM.return_value.chat.return_value = MOCK_PLAN_JSON
            result = planner_node(state)

        assert "F1" in result.pending_plans
        assert result.pending_plans["F1"] is result.execution_plan.finding_plans["F1"]

    def test_waves_in_execution_plan(self):
        """With a chain dependency, waves should split correctly."""
        f1 = make_finding("F1", blast_radius=2, dependency_node_id="n1")
        f2 = make_finding("F2", blast_radius=0, dependency_node_id="n2",
                          depends_on_node_ids=["n1"])
        state = PlannerState(
            session_id="s", target_path=Path("/tmp"), selected_findings=[f1, f2]
        )
        with patch("qsma.planner.LLMClient") as MockLLM:
            MockLLM.return_value.chat.return_value = MOCK_PLAN_JSON
            result = planner_node(state)

        waves = result.execution_plan.waves
        assert len(waves) >= 2
        assert "F1" in waves[0]
        f2_wave = next(i for i, w in enumerate(waves) if "F2" in w)
        assert f2_wave > 0


# ---------------------------------------------------------------------------
# run_planner (convenience entry point)
# ---------------------------------------------------------------------------

class TestRunPlanner:

    def test_returns_state_with_execution_plan(self):
        findings = [make_finding("F1"), make_finding("F2")]
        with patch("qsma.planner.LLMClient") as MockLLM:
            MockLLM.return_value.chat.return_value = MOCK_PLAN_JSON
            state = run_planner(findings, "s1", Path("/tmp"))

        assert state.execution_plan is not None
        assert len(state.execution_plan.finding_plans) == 2

    def test_dry_run_flag_preserved(self):
        findings = [make_finding("F1")]
        with patch("qsma.planner.LLMClient") as MockLLM:
            MockLLM.return_value.chat.return_value = MOCK_PLAN_JSON
            state = run_planner(findings, "s2", Path("/tmp"), dry_run=True)

        assert state.dry_run is True

    def test_multi_language_findings_all_planned(self):
        findings = [
            make_finding("F1", language="python"),
            make_finding("F2", language="java"),
            make_finding("F3", language="go"),
        ]
        with patch("qsma.planner.LLMClient") as MockLLM:
            MockLLM.return_value.chat.return_value = MOCK_PLAN_JSON
            state = run_planner(findings, "s3", Path("/tmp"))

        assert set(state.execution_plan.finding_plans.keys()) == {"F1", "F2", "F3"}
        # All three should have had LLM called
        assert MockLLM.return_value.chat.call_count == 3
