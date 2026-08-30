"""
Unit tests for qsma.reporter.

Covers:
  - build_scan_report aggregates counts correctly from a list of findings
  - findings are sorted by risk severity (CRITICAL first) then severity_score
  - format_text / format_json / format_markdown all contain key content markers
  - format_json round-trips through ScanReport.model_validate_json
"""

from __future__ import annotations

from pathlib import Path

from qsma.reporter import build_scan_report, finding_rows, format_json, format_markdown, format_text
from qsma.utils.models import (
    Algorithm,
    CodebaseSnapshot,
    CodeLocation,
    CryptoFinding,
    QuantumRisk,
    ScanReport,
    SourceFile,
)


def make_finding(
    id: str,
    algorithm: Algorithm = Algorithm.RSA,
    risk: QuantumRisk = QuantumRisk.CRITICAL,
    severity_score: float = 9.0,
    file: str = "app/crypto.py",
    line: int = 5,
) -> CryptoFinding:
    return CryptoFinding(
        id=id,
        algorithm=algorithm,
        risk=risk,
        algorithm_risk_score=10.0,
        migration_risk_score=5.0,
        severity_score=severity_score,
        location=CodeLocation(file=Path(file), line_start=line, line_end=line),
        usage_type="key_generation",
        explanation="RSA key generation detected.",
        recommendation="Migrate to ML-KEM (Kyber).",
        blast_radius=2,
    )


def make_snapshot(file_count: int = 10) -> CodebaseSnapshot:
    return CodebaseSnapshot(
        root_path=Path("/tmp/project"),
        files=[
            SourceFile(path=Path(f"f{i}.py"), content="", language="python")
            for i in range(file_count)
        ],
        file_count=file_count,
    )


def test_build_scan_report_counts_by_risk():
    findings = [
        make_finding("QSMA-0001", risk=QuantumRisk.CRITICAL),
        make_finding("QSMA-0002", risk=QuantumRisk.HIGH),
        make_finding("QSMA-0003", risk=QuantumRisk.HIGH),
        make_finding("QSMA-0004", risk=QuantumRisk.LOW),
    ]
    report = build_scan_report(Path("/tmp/project"), make_snapshot(5), findings, 1.23)

    assert report.total_files_scanned == 5
    assert report.total_findings == 4
    assert report.critical_count == 1
    assert report.high_count == 2
    assert report.medium_count == 0
    assert report.low_count == 1
    assert report.scan_duration_seconds == 1.23


def test_build_scan_report_sorts_critical_first():
    findings = [
        make_finding("QSMA-0001", risk=QuantumRisk.LOW, severity_score=1.0),
        make_finding("QSMA-0002", risk=QuantumRisk.CRITICAL, severity_score=9.5),
        make_finding("QSMA-0003", risk=QuantumRisk.HIGH, severity_score=6.0),
    ]
    report = build_scan_report(Path("/tmp/project"), make_snapshot(), findings, 0.1)

    assert [f.id for f in report.findings] == ["QSMA-0002", "QSMA-0003", "QSMA-0001"]


def test_build_scan_report_orders_within_same_risk_by_severity():
    findings = [
        make_finding("QSMA-0001", risk=QuantumRisk.HIGH, severity_score=5.5),
        make_finding("QSMA-0002", risk=QuantumRisk.HIGH, severity_score=7.9),
    ]
    report = build_scan_report(Path("/tmp/project"), make_snapshot(), findings, 0.1)

    assert [f.id for f in report.findings] == ["QSMA-0002", "QSMA-0001"]


def test_finding_rows_shape():
    findings = [make_finding("QSMA-0001")]
    report = build_scan_report(Path("/tmp/project"), make_snapshot(), findings, 0.1)

    rows = finding_rows(report)
    assert len(rows) == 1
    assert rows[0]["id"] == "QSMA-0001"
    assert rows[0]["file"] == "app/crypto.py:5"
    assert rows[0]["recommendation"] == "Migrate to ML-KEM (Kyber)."


def test_format_text_contains_key_markers():
    findings = [make_finding("QSMA-0001")]
    report = build_scan_report(Path("/tmp/project"), make_snapshot(3), findings, 0.5)

    text = format_text(report)
    assert "QSMA Scan Report" in text
    assert "QSMA-0001" in text
    assert "Critical: 1" in text


def test_format_markdown_contains_table():
    findings = [make_finding("QSMA-0001")]
    report = build_scan_report(Path("/tmp/project"), make_snapshot(3), findings, 0.5)

    md = format_markdown(report)
    assert "| QSMA-0001 |" in md
    assert md.startswith("# QSMA Scan Report")


def test_format_json_round_trips():
    findings = [make_finding("QSMA-0001")]
    report = build_scan_report(Path("/tmp/project"), make_snapshot(3), findings, 0.5)

    json_str = format_json(report)
    reloaded = ScanReport.model_validate_json(json_str)
    assert reloaded.total_findings == 1
    assert reloaded.findings[0].id == "QSMA-0001"


def test_build_scan_report_empty_findings():
    report = build_scan_report(Path("/tmp/project"), make_snapshot(0), [], 0.0)
    assert report.total_findings == 0
    assert report.findings == []
    assert report.critical_count == 0
