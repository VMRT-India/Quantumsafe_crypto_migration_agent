"""
qsma.reporter
=============
Public API for the Reporter module.

Assembles a ScanReport from pipeline outputs and formats it for CLI display.
No business logic lives in the CLI module (ARCHITECTURE.md) — Reporter owns
aggregation/sorting/formatting; the CLI only renders the returned strings
(or, for the text format, builds a rich.Table from the returned row data).

Usage::

    from qsma.reporter import build_scan_report, format_text, format_json, format_markdown
    report = build_scan_report(target_path, snapshot, findings, duration_seconds)
    print(format_text(report))
"""

from __future__ import annotations

from pathlib import Path

from qsma.utils.models import CodebaseSnapshot, CryptoFinding, DependencyGraph, QuantumRisk, ScanReport

_RISK_ORDER: dict[QuantumRisk, int] = {
    QuantumRisk.CRITICAL: 0,
    QuantumRisk.HIGH: 1,
    QuantumRisk.MEDIUM: 2,
    QuantumRisk.LOW: 3,
    QuantumRisk.INFO: 4,
}


def build_scan_report(
    target_path: Path,
    snapshot: CodebaseSnapshot,
    findings: list[CryptoFinding],
    duration_seconds: float,
    dependency_graph: DependencyGraph | None = None,
) -> ScanReport:
    """Assemble a ScanReport from the outputs of Ingestion + Classifier."""
    counts = {risk: 0 for risk in QuantumRisk}
    for finding in findings:
        counts[finding.risk] += 1

    return ScanReport(
        target_path=target_path,
        findings=sorted(findings, key=lambda f: (_RISK_ORDER[f.risk], -f.severity_score)),
        total_files_scanned=snapshot.file_count,
        total_findings=len(findings),
        critical_count=counts[QuantumRisk.CRITICAL],
        high_count=counts[QuantumRisk.HIGH],
        medium_count=counts[QuantumRisk.MEDIUM],
        low_count=counts[QuantumRisk.LOW],
        scan_duration_seconds=duration_seconds,
        dependency_graph=dependency_graph,
    )


def finding_rows(report: ScanReport) -> list[dict[str, str]]:
    """Flat row data for each finding — for the CLI to render as a rich.Table."""
    return [
        {
            "id": f.id,
            "risk": f.risk.value,
            "algorithm": f.algorithm.value,
            "severity": f"{f.severity_score:.1f}",
            "file": f"{f.location.file}:{f.location.line_start}",
            "usage_type": f.usage_type,
            "blast_radius": str(f.blast_radius),
            "recommendation": f.recommendation,
        }
        for f in report.findings
    ]


def format_text(report: ScanReport) -> str:
    """Plain-text summary (used as a fallback / for --output text files)."""
    lines = [
        "QSMA Scan Report",
        f"Target:           {report.target_path}",
        f"Files scanned:    {report.total_files_scanned}",
        f"Duration:         {report.scan_duration_seconds:.2f}s",
        f"Total findings:   {report.total_findings}",
        f"  Critical: {report.critical_count}  High: {report.high_count}  "
        f"Medium: {report.medium_count}  Low: {report.low_count}",
        "",
    ]
    for row in finding_rows(report):
        lines.append(
            f"[{row['risk']:<8}] {row['id']}  {row['algorithm']:<12} "
            f"sev={row['severity']:<4} blast={row['blast_radius']:<3} {row['file']}"
        )
        lines.append(f"           -> {row['recommendation']}")
    return "\n".join(lines)


def format_json(report: ScanReport) -> str:
    return report.model_dump_json(indent=2)


def format_markdown(report: ScanReport) -> str:
    lines = [
        "# QSMA Scan Report",
        "",
        f"- **Target**: {report.target_path}",
        f"- **Files Scanned**: {report.total_files_scanned}",
        f"- **Duration**: {report.scan_duration_seconds:.2f}s",
        f"- **Total Findings**: {report.total_findings} "
        f"(Critical: {report.critical_count}, High: {report.high_count}, "
        f"Medium: {report.medium_count}, Low: {report.low_count})",
        "",
        "| ID | Risk | Algorithm | Severity | Location | Recommendation |",
        "|---|---|---|---|---|---|",
    ]
    for row in finding_rows(report):
        lines.append(
            f"| {row['id']} | {row['risk']} | {row['algorithm']} | {row['severity']} "
            f"| {row['file']} | {row['recommendation']} |"
        )
    return "\n".join(lines)


__all__ = [
    "build_scan_report",
    "finding_rows",
    "format_text",
    "format_json",
    "format_markdown",
]
