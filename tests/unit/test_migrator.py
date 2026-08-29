"""
Unit tests for qsma.migrator (migrator_node, run_migrator)
and qsma.migrator.patcher (apply_patch).
"""

from __future__ import annotations

import textwrap
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from qsma.llm.client import LLMClient
from qsma.migrator import migrator_node, run_migrator
from qsma.migrator.patcher import apply_patch
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
    line_start: int = 1,
    line_end: int = 3,
    snippet: str = "private_key = rsa.generate_private_key(65537, 2048)",
    file: Path | None = None,
) -> CryptoFinding:
    return CryptoFinding(
        id=id,
        algorithm=algorithm,
        risk=QuantumRisk.CRITICAL,
        algorithm_risk_score=10.0,
        migration_risk_score=7.0,
        severity_score=8.8,
        location=CodeLocation(
            file=file or Path("src/crypto.py"),
            line_start=line_start,
            line_end=line_end,
            snippet=snippet,
        ),
        usage_type="signature",
        library="cryptography",
        explanation="RSA is quantum-vulnerable.",
        recommendation="Use ML-DSA.",
        metadata={"language": "python"},
    )


def make_plan(
    finding_id: str = "QSMA-0001",
    strategy: str = "llm_assisted",
    target: Algorithm = Algorithm.DILITHIUM,
) -> MigrationPlan:
    return MigrationPlan(
        finding_id=finding_id,
        strategy=strategy,
        target_algorithm=target,
        description="Replace RSA with ML-DSA.",
        estimated_complexity="medium",
        requires_dependency_update=True,
        new_dependencies=["pqcrypto"],
        transformation_hints={"source_algorithm": "RSA"},
    )


def make_state(
    finding: CryptoFinding | None = None,
    plan: MigrationPlan | None = None,
    retry_count: int = 0,
    dry_run: bool = False,
) -> MigrationSessionState:
    f = finding or make_finding()
    p = plan or make_plan(finding_id=f.id)
    return MigrationSessionState(
        session_id="test-session",
        target_path=Path("/tmp/project"),
        selected_findings=[f],
        pending_plans={f.id: p},
        current_finding_id=f.id,
        retry_count=retry_count,
        dry_run=dry_run,
    )


TRANSFORMED_CODE = "private_key, public_key = dilithium.generate_keys()\n"


# ---------------------------------------------------------------------------
# migrator_node
# ---------------------------------------------------------------------------

class TestMigratorNode:

    def test_no_current_finding_id_returns_done(self):
        state = MigrationSessionState(
            session_id="s",
            target_path=Path("/tmp"),
            current_finding_id=None,
        )
        result = migrator_node(state)
        assert result.routing_signal == "done"

    def test_manual_only_plan_routes_escalate(self):
        finding = make_finding()
        plan = make_plan(strategy="manual_only")
        state = make_state(finding=finding, plan=plan)

        result = migrator_node(state)

        assert result.routing_signal == "escalate"
        assert result.transformation_results[0].success is False
        assert finding.migration_status == MigrationStatus.SKIPPED

    def test_max_retries_exceeded_routes_escalate(self):
        state = make_state(retry_count=3)
        with patch("qsma.migrator.LLMClient"):
            result = migrator_node(state)

        assert result.routing_signal == "escalate"
        assert "Max retries" in result.transformation_results[0].error_message

    def test_llm_failure_routes_escalate(self):
        from qsma.llm.client import LLMError

        state = make_state()
        with patch("qsma.migrator.LLMClient") as MockLLM:
            MockLLM.return_value.chat.side_effect = LLMError("connection refused")
            result = migrator_node(state)

        assert result.routing_signal == "escalate"
        assert result.transformation_results[0].success is False

    def test_successful_dry_run_routes_validate(self, tmp_path):
        source = tmp_path / "crypto.py"
        source.write_text(
            "import rsa\n"
            "private_key = rsa.generate_private_key(65537, 2048)\n"
            "print('done')\n",
            encoding="utf-8",
        )
        finding = make_finding(file=source, line_start=2, line_end=2, snippet="private_key = rsa.generate_private_key(65537, 2048)")
        plan = make_plan(finding_id=finding.id)
        state = make_state(finding=finding, plan=plan, dry_run=True)

        with patch("qsma.migrator.call_llm_transform") as mock_transform:
            mock_transform.return_value = (True, TRANSFORMED_CODE)
            result = migrator_node(state)

        assert result.routing_signal == "validate"
        assert result.transformation_results[0].success is True
        # dry_run → file should NOT be modified
        assert source.read_text().count("rsa") > 0

    def test_successful_real_write(self, tmp_path):
        source = tmp_path / "crypto.py"
        source.write_text(
            "import rsa\n"
            "private_key = rsa.generate_private_key(65537, 2048)\n"
            "print('done')\n",
            encoding="utf-8",
        )
        finding = make_finding(file=source, line_start=2, line_end=2, snippet="private_key = rsa.generate_private_key(65537, 2048)")
        plan = make_plan(finding_id=finding.id)
        state = make_state(finding=finding, plan=plan, dry_run=False)

        with patch("qsma.migrator.call_llm_transform") as mock_transform:
            mock_transform.return_value = (True, TRANSFORMED_CODE)
            result = migrator_node(state)

        assert result.routing_signal == "validate"
        written = source.read_text()
        assert "dilithium" in written

    def test_no_plan_routes_escalate(self):
        finding = make_finding()
        state = MigrationSessionState(
            session_id="s",
            target_path=Path("/tmp"),
            selected_findings=[finding],
            pending_plans={},            # no plan
            current_finding_id=finding.id,
        )
        result = migrator_node(state)
        assert result.routing_signal == "escalate"


# ---------------------------------------------------------------------------
# apply_patch (patcher unit tests)
# ---------------------------------------------------------------------------

class TestApplyPatch:

    def test_replaces_target_lines(self, tmp_path):
        src = tmp_path / "f.py"
        src.write_text("a = 1\nb = 2\nc = 3\n", encoding="utf-8")

        ok, detail = apply_patch(src, "b = 99\n", line_start=2, line_end=2)
        assert ok
        assert src.read_text() == "a = 1\nb = 99\nc = 3\n"

    def test_dry_run_does_not_write(self, tmp_path):
        src = tmp_path / "f.py"
        original = "a = 1\nb = 2\nc = 3\n"
        src.write_text(original, encoding="utf-8")

        ok, diff = apply_patch(src, "b = 99\n", line_start=2, line_end=2, dry_run=True)
        assert ok
        assert "-b = 2" in diff
        assert src.read_text() == original   # unchanged

    def test_out_of_range_returns_false(self, tmp_path):
        src = tmp_path / "f.py"
        src.write_text("x = 1\n", encoding="utf-8")

        ok, msg = apply_patch(src, "y = 2\n", line_start=5, line_end=5)
        assert not ok
        assert "out of bounds" in msg

    def test_syntax_error_in_patch_returns_false(self, tmp_path):
        src = tmp_path / "f.py"
        src.write_text("x = 1\n", encoding="utf-8")

        ok, msg = apply_patch(src, "def broken(\n", line_start=1, line_end=1)
        assert not ok
        assert "syntax error" in msg.lower()

    def test_multiline_replacement(self, tmp_path):
        src = tmp_path / "f.py"
        src.write_text(
            "line1\n"
            "old_start\n"
            "old_middle\n"
            "old_end\n"
            "line5\n",
            encoding="utf-8",
        )
        replacement = "new_start\nnew_end\n"
        ok, _ = apply_patch(src, replacement, line_start=2, line_end=4)
        assert ok
        lines = src.read_text().splitlines()
        assert lines[0] == "line1"
        assert lines[1] == "new_start"
        assert lines[2] == "new_end"
        assert lines[3] == "line5"

    def test_diff_contains_plus_minus_markers(self, tmp_path):
        src = tmp_path / "f.py"
        src.write_text("x = 1\n", encoding="utf-8")
        ok, diff = apply_patch(src, "x = 2\n", line_start=1, line_end=1, dry_run=True)
        assert ok
        assert "-x = 1" in diff
        assert "+x = 2" in diff


# ---------------------------------------------------------------------------
# run_migrator (convenience entry point)
# ---------------------------------------------------------------------------

class TestRunMigrator:

    def test_processes_all_pending_plans(self, tmp_path):
        src1 = tmp_path / "a.py"
        src2 = tmp_path / "b.py"
        src1.write_text("key = rsa.generate_private_key(65537, 2048)\n")
        src2.write_text("key = rsa.generate_private_key(65537, 2048)\n")

        f1 = make_finding("QSMA-0001", file=src1, line_start=1, line_end=1)
        f2 = make_finding("QSMA-0002", file=src2, line_start=1, line_end=1)
        p1 = make_plan("QSMA-0001")
        p2 = make_plan("QSMA-0002")

        state = MigrationSessionState(
            session_id="s",
            target_path=tmp_path,
            selected_findings=[f1, f2],
            pending_plans={"QSMA-0001": p1, "QSMA-0002": p2},
        )

        with patch("qsma.migrator.call_llm_transform") as mock_tx:
            mock_tx.return_value = (True, "key, pub = dilithium.generate_keys()\n")
            final = run_migrator(state)

        assert len(final.transformation_results) == 2
        assert all(r.success for r in final.transformation_results)
