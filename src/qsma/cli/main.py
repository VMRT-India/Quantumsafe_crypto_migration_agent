"""
qsma.cli.main
=============
Top-level Click group that wires together all CLI sub-commands.
"""

from __future__ import annotations

import logging
import time
import uuid
from pathlib import Path

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from qsma.agent import run_migration_session
from qsma.analyzer import analyse_snapshot
from qsma.classifier import classify
from qsma.detector import detect
from qsma.ingestion import collect_snapshot
from qsma.reporter import build_scan_report, finding_rows, format_json, format_markdown
from qsma.utils.models import IngestionConfig, ScanReport
from qsma.validator.node import run_syntax_check, run_test_suite

console = Console()
logger = logging.getLogger(__name__)

CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"]}

# All extensions the Analyzer/Detector have tree-sitter grammars for
# (walker.py's default IngestionConfig only includes .py — override it here
# so `qsma scan` picks up every supported language by default).
_ALL_SUPPORTED_EXTENSIONS = [".py", ".java", ".go", ".c", ".h", ".cc", ".cpp", ".rs"]


@click.group(context_settings=CONTEXT_SETTINGS)
@click.version_option(version="0.1.0", prog_name="qsma")
def cli() -> None:
    """Quantum-Safe Crypto Migration Agent."""
    if click.get_current_context().invoked_subcommand is None:
        click.echo(click.get_current_context().get_help())


def _run_scan_pipeline(path: Path) -> ScanReport:
    """Ingestion -> Analyzer -> Detector -> Classifier -> ScanReport."""
    start = time.monotonic()
    session_id = str(uuid.uuid4())

    config = IngestionConfig(extensions=_ALL_SUPPORTED_EXTENSIONS)
    snapshot = collect_snapshot(path, config)
    analysis = analyse_snapshot(snapshot)
    hits, graph = detect(analysis, session_id=session_id, root_path=path)
    findings = classify(hits, graph)

    duration = time.monotonic() - start
    return build_scan_report(path, snapshot, findings, duration, dependency_graph=graph)


def _render_report(report: ScanReport, fmt: str, output: Path | None) -> None:
    if fmt == "json":
        output_data = format_json(report)
        if output:
            output.write_text(output_data)
            console.print(f"[green]✓[/green] Report written to {output}")
        else:
            console.print_json(output_data)
    elif fmt == "markdown":
        md_content = format_markdown(report)
        if output:
            output.write_text(md_content)
            console.print(f"[green]✓[/green] Report written to {output}")
        else:
            console.print(md_content)
    else:
        table = Table(title="Scan Summary")
        table.add_column("ID", style="cyan")
        table.add_column("Risk")
        table.add_column("Algorithm")
        table.add_column("Severity", justify="right")
        table.add_column("Location")
        table.add_column("Recommendation")

        risk_style = {
            "CRITICAL": "bold red",
            "HIGH": "yellow",
            "MEDIUM": "cyan",
            "LOW": "green",
            "INFO": "dim",
        }
        for row in finding_rows(report):
            style = risk_style.get(row["risk"], "white")
            table.add_row(
                row["id"],
                f"[{style}]{row['risk']}[/{style}]",
                row["algorithm"],
                row["severity"],
                row["file"],
                row["recommendation"],
            )

        console.print(
            f"Target: {report.target_path}  |  Files scanned: {report.total_files_scanned}  |  "
            f"Duration: {report.scan_duration_seconds:.2f}s"
        )
        console.print(
            f"Total findings: {report.total_findings}  "
            f"([bold red]Critical: {report.critical_count}[/bold red] "
            f"[yellow]High: {report.high_count}[/yellow] "
            f"[cyan]Medium: {report.medium_count}[/cyan] "
            f"[green]Low: {report.low_count}[/green])"
        )
        console.print(table)
        if output:
            output.write_text(format_json(report))
            console.print(f"[green]✓[/green] Full JSON report written to {output}")


@cli.command()
@click.argument(
    "path",
    default=".",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
)
@click.option("--format", "fmt", type=click.Choice(["text", "json", "markdown"]), default="text")
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None)
def scan(path: Path, fmt: str, output: Path | None) -> None:
    """Scan a codebase for quantum-vulnerable cryptographic usage."""
    console.print(f"[bold cyan]qsma scan[/bold cyan] — target: {path}")
    try:
        with Progress(
            SpinnerColumn(), TextColumn("[progress.description]{task.description}")
        ) as progress:
            task = progress.add_task(
                "Running Ingestion → Analyzer → Detector → Classifier...", total=None
            )
            report = _run_scan_pipeline(path)
            progress.update(task, description="Scan complete.")

        _render_report(report, fmt, output)

    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/yellow]")
        raise click.Abort() from None
    except Exception as e:
        console.print(f"[red]✗[/red] Scan failed: {e}")
        logger.exception("Scan pipeline error")
        raise click.Abort() from e


@cli.command()
@click.argument(
    "path",
    default=".",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
)
@click.option("--findings", type=click.Path(exists=True, path_type=Path), default=None)
@click.option("--format", "fmt", type=click.Choice(["text", "json", "markdown"]), default="text")
def report(path: Path, findings: Path | None, fmt: str) -> None:
    """Display a formatted findings report for a previously scanned codebase."""
    console.print(f"[bold cyan]qsma report[/bold cyan] — target: {path}")
    try:
        if findings:
            console.print(f"Loading findings from {findings}...")
            scan_report = ScanReport.model_validate_json(findings.read_text())
        else:
            console.print("[yellow]No --findings file provided. Running fresh scan...[/yellow]")
            scan_report = _run_scan_pipeline(path)

        _render_report(scan_report, fmt, None)
    except Exception as e:
        console.print(f"[red]✗[/red] Report generation failed: {e}")
        raise click.Abort() from e


@cli.command()
@click.argument(
    "path",
    default=".",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
)
@click.option("--finding-id", multiple=True, help="Migrate specific finding ID(s) only.")
@click.option("--dry-run", is_flag=True, default=False)
@click.option("--auto", is_flag=True, default=False)
@click.option("--resume", default=None, help="Resume an interrupted session by session ID.")
def migrate(
    path: Path, finding_id: tuple[str, ...], dry_run: bool, auto: bool, resume: str | None
) -> None:
    """Apply quantum-safe migrations."""
    console.print(f"[bold cyan]qsma migrate[/bold cyan] — target: {path}")
    try:
        if resume:
            console.print(f"[bold blue]Resuming[/bold blue] session: {resume}")
            session_id = resume
        else:
            session_id = str(uuid.uuid4())
            console.print(f"[bold blue]Starting new[/bold blue] migration session: {session_id}")

        console.print("Running scan to resolve findings...")
        scan_report = _run_scan_pipeline(path)
        all_findings = {f.id: f for f in scan_report.findings}

        if finding_id:
            selected = [all_findings[fid] for fid in finding_id if fid in all_findings]
        elif auto:
            selected = [f for f in scan_report.findings if f.risk.value in ("CRITICAL", "HIGH")]
        else:
            selected = []

        console.print(
            f"Selected findings: {', '.join(f.id for f in selected) if selected else 'None'}"
        )
        console.print(f"Dry-run mode: {'[yellow]Yes[/yellow]' if dry_run else '[green]No[/green]'}")

        if not selected:
            console.print(
                "[yellow]No findings selected for migration. "
                "Use `qsma chat`, `--finding-id`, or `--auto`.[/yellow]"
            )
            return

        console.print("\n[bold]Executing Migration Graph (Planner → Migrator → Validator)[/bold]")
        with Progress(
            SpinnerColumn(), TextColumn("[progress.description]{task.description}")
        ) as progress:
            task = progress.add_task("Running agentic migration loop...", total=None)
            final_state = run_migration_session(session_id, path, selected, dry_run=dry_run)
            progress.update(task, description="Migration loop complete.")

        passed = sum(1 for v in final_state.validation_results if v.passed)
        failed = len(final_state.validation_results) - passed
        console.print(
            f"[green]✓[/green] Migration session {session_id} finished. "
            f"{passed} passed, {failed} failed. Run `qsma validate` or `qsma report`."
        )
    except KeyboardInterrupt:
        console.print(
            "\n[yellow]Migration interrupted. Session state can be resumed with --resume.[/yellow]"
        )
        raise click.Abort() from None
    except Exception as e:
        console.print(f"[red]✗[/red] Migration failed: {e}")
        logger.exception("Migration pipeline error")
        raise click.Abort() from e


@cli.command()
@click.argument(
    "path",
    default=".",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
)
@click.option("--timeout", default=120, show_default=True, help="Validation timeout (seconds).")
def validate(path: Path, timeout: int) -> None:
    """Run post-migration validation (syntax + tests) on a codebase."""
    console.print(f"[bold cyan]qsma validate[/bold cyan] — target: {path}")
    try:
        py_files = list(path.rglob("*.py"))
        with Progress(
            SpinnerColumn(), TextColumn("[progress.description]{task.description}")
        ) as progress:
            task = progress.add_task(
                f"Running syntax checks and test suites (timeout: {timeout}s)...", total=None
            )
            syntax_ok, syntax_error = run_syntax_check(py_files)
            tests_ok, test_summary, error_output = (True, "Skipped (syntax failed)", "")
            if syntax_ok:
                tests_ok, test_summary, error_output = run_test_suite(path, timeout=timeout)
            progress.update(task, description="Validation complete.")

        if syntax_ok and tests_ok:
            console.print(f"[green]✓[/green] All modified files pass syntax checks. {test_summary}.")
        else:
            console.print("[red]✗[/red] Validation failed.")
            if not syntax_ok:
                console.print(f"  Syntax error: {syntax_error}")
            if not tests_ok:
                console.print(f"  {test_summary}")
                if error_output:
                    console.print(error_output)
            raise click.Abort()
    except click.Abort:
        raise
    except Exception as e:
        console.print(f"[red]✗[/red] Validation failed: {e}")
        logger.exception("Validation error")
        raise click.Abort() from e


@cli.command()
@click.argument(
    "path",
    default=".",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
)
@click.option("--scan-first", is_flag=True, default=True)
@click.option("--findings", type=click.Path(exists=True, path_type=Path), default=None)
def chat(path: Path, scan_first: bool, findings: Path | None) -> None:
    """Talk to the AI advisor about your scan results in natural language."""
    console.print(f"[bold magenta]qsma chat[/bold magenta] — target: {path}")
    try:
        if scan_first and not findings:
            console.print("[dim]Running preliminary scan to load context...[/dim]")
        elif findings:
            console.print(f"[dim]Loading findings from {findings}...[/dim]")
        else:
            console.print(
                "[yellow]No findings provided. Run `qsma scan` first or use --findings.[/yellow]"
            )
            return

        console.print("\n[bold green]Advisor Ready[/bold green]. Ask questions or type 'help'.")
        console.print(
            "[yellow]Advisor module integration pending. See PROJECT_CONTEXT.md §6.10[/yellow]"
        )
        console.print("[dim]Mocking selection of QSMA-0001, QSMA-0002 for demonstration.[/dim]")
        selected_ids = ["QSMA-0001", "QSMA-0002"]

        if selected_ids:
            console.print(f"\n[bold]Selected for migration:[/bold] {', '.join(selected_ids)}")
            if click.confirm("Proceed with migration for these findings?", default=True):
                ctx = click.get_current_context()
                ctx.invoke(migrate, path=path, finding_id=tuple(selected_ids))
        else:
            console.print("[dim]No findings selected. Exiting.[/dim]")
    except KeyboardInterrupt:
        console.print("\n[yellow]Advisor session ended.[/yellow]")
        raise click.Abort() from None
    except Exception as e:
        console.print(f"[red]✗[/red] Advisor failed: {e}")
        logger.exception("Advisor error")
        raise click.Abort() from e


if __name__ == "__main__":
    cli()
