"""
Unit tests for qsma.cli.main — exercised end-to-end (real ingestion/analyzer/
detector/classifier pipeline) against the checked-in fixture projects, with
LLM_PROVIDER forced to "mock" so `migrate` never hits the network.

Covers:
  - `scan --format json` against a real fixture produces valid JSON with
    real findings (not the old mocked QSMA-0001 stub).
  - `scan --format markdown` / default text format render without error.
  - `report --findings <file>` reloads a previously saved ScanReport.
  - `validate` runs a real syntax check against the fixture.
  - `migrate --auto --dry-run` runs the full agent graph without touching disk.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from qsma.cli.main import cli

FIXTURE = Path(__file__).parent.parent / "fixtures" / "sample_projects" / "python_rsa"


@pytest.fixture(autouse=True)
def mock_llm_provider(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "mock")


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


def test_scan_json_produces_real_findings(runner: CliRunner):
    result = runner.invoke(cli, ["scan", str(FIXTURE), "--format", "json"])

    assert result.exit_code == 0, result.output
    start = result.output.index("{")
    payload = json.loads(result.output[start:])

    assert payload["total_findings"] > 0
    assert all(f["algorithm"] == "RSA" for f in payload["findings"])


def test_scan_text_format_runs_without_error(runner: CliRunner):
    result = runner.invoke(cli, ["scan", str(FIXTURE)])
    assert result.exit_code == 0, result.output
    assert "Scan Summary" in result.output or "QSMA" in result.output


def test_scan_markdown_format(runner: CliRunner):
    result = runner.invoke(cli, ["scan", str(FIXTURE), "--format", "markdown"])
    assert result.exit_code == 0, result.output
    assert "# QSMA Scan Report" in result.output


def test_scan_writes_output_file(runner: CliRunner, tmp_path):
    out_file = tmp_path / "report.json"
    result = runner.invoke(cli, ["scan", str(FIXTURE), "--format", "json", "--output", str(out_file)])
    assert result.exit_code == 0, result.output
    assert out_file.exists()
    data = json.loads(out_file.read_text())
    assert data["total_findings"] > 0


def test_report_reloads_saved_findings(runner: CliRunner, tmp_path):
    out_file = tmp_path / "report.json"
    scan_result = runner.invoke(
        cli, ["scan", str(FIXTURE), "--format", "json", "--output", str(out_file)]
    )
    assert scan_result.exit_code == 0, scan_result.output

    report_result = runner.invoke(cli, ["report", str(FIXTURE), "--findings", str(out_file)])
    assert report_result.exit_code == 0, report_result.output
    assert "Loading findings from" in report_result.output


def test_validate_runs_syntax_check(runner: CliRunner):
    result = runner.invoke(cli, ["validate", str(FIXTURE)])
    assert result.exit_code == 0, result.output
    assert "pass syntax checks" in result.output


def test_migrate_auto_dry_run_completes(runner: CliRunner):
    result = runner.invoke(cli, ["migrate", str(FIXTURE), "--auto", "--dry-run"])
    assert result.exit_code == 0, result.output
    assert "Migration session" in result.output
    assert "finished" in result.output


def test_migrate_no_findings_selected_without_auto_or_ids(runner: CliRunner):
    result = runner.invoke(cli, ["migrate", str(FIXTURE)])
    assert result.exit_code == 0, result.output
    assert "No findings selected" in result.output
