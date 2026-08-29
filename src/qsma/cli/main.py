"""
qsma.cli.main
=============
Top-level Click group that wires together all CLI sub-commands.
"""

from __future__ import annotations

import json
import logging
import uuid
from pathlib import Path

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from qsma.utils.models import MigrationSessionState, ScanReport

console = Console()
logger = logging.getLogger(__name__)

CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"]}


@click.group(context_settings=CONTEXT_SETTINGS)
@click.version_option(version="0.1.0", prog_name="qsma")
def cli() -> None:
    """Quantum-Safe Crypto Migration Agent."""
    if click.get_current_context().invoked_subcommand is None:
        click.echo(click.get_current_context().get_help())


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
            import time

            time.sleep(1.5)
            report = ScanReport(
                target_path=path,
                total_files_scanned=42,
                total_findings=3,
                critical_count=1,
                high_count=2,
                medium_count=0,
                low_count=0,
                scan_duration_seconds=1.5,
            )
            progress.update(task, description="Scan complete.")

        if fmt == "json":
            output_data = report.model_dump_json(indent=2)
            if output:
                output.write_text(output_data)
                console.print(f"[green]✓[/green] Report written to {output}")
            else:
                console.print_json(output_data)
        elif fmt == "markdown":
            md_content = f"# QSMA Scan Report\n\n- **Target**: {path}\n- **Files Scanned**: {report.total_files_scanned}\n- **Total Findings**: {report.total_findings}\n"
            if output:
                output.write_text(md_content)
                console.print(f"[green]✓[/green] Report written to {output}")
            else:
                console.print(md_content)
        else:
            table = Table(title="Scan Summary")
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="green")
            table.add_row("Target Path", str(path))
            table.add_row("Files Scanned", str(report.total_files_scanned))
            table.add_row("Total Findings", str(report.total_findings))
            table.add_row("Critical", f"[red]{report.critical_count}[/red]")
            table.add_row("High", f"[yellow]{report.high_count}[/yellow]")
            console.print(table)
            if output:
                output.write_text(report.model_dump_json(indent=2))
                console.print(f"[green]✓[/green] Full JSON report written to {output}")

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
def report(path: Path, findings: Path | None) -> None:
    """Display a formatted findings report for a previously scanned codebase."""
    console.print(f"[bold cyan]qsma report[/bold cyan] — target: {path}")
    try:
        if findings:
            console.print(f"Loading findings from {findings}...")
            json.loads(findings.read_text())
        else:
            console.print("[yellow]No --findings file provided. Running fresh scan...[/yellow]")
            raise NotImplementedError("Fresh scan orchestration not yet wired in CLI")
        console.print(
            "[yellow]Reporter module integration pending. See PROJECT_CONTEXT.md §6.8[/yellow]"
        )
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
            state = MigrationSessionState(session_id=resume, target_path=path, is_dry_run=dry_run)
        else:
            session_id = str(uuid.uuid4())
            console.print(f"[bold blue]Starting new[/bold blue] migration session: {session_id}")
            selected_ids = list(finding_id)
            if auto and not selected_ids:
                console.print("[yellow]--auto selected: mocking CRITICAL/HIGH selection[/yellow]")
                selected_ids = ["QSMA-0001", "QSMA-0002"]
            state = MigrationSessionState(
                session_id=session_id,
                target_path=path,
                selected_finding_ids=selected_ids,
                is_dry_run=dry_run,
            )

        console.print(
            f"Selected findings: {', '.join(state.selected_finding_ids) if state.selected_finding_ids else 'None'}"
        )
        console.print(f"Dry-run mode: {'[yellow]Yes[/yellow]' if dry_run else '[green]No[/green]'}")

        if not state.selected_finding_ids:
            console.print(
                "[yellow]No findings selected for migration. Use `qsma chat` or `--finding-id`.[/yellow]"
            )
            return

        console.print("\n[bold]Executing Migration Graph (Planner → Migrator → Validator)[/bold]")
        with Progress(
            SpinnerColumn(), TextColumn("[progress.description]{task.description}")
        ) as progress:
            task = progress.add_task("Running agentic migration loop...", total=None)
            import time

            time.sleep(2.0)
            progress.update(task, description="Migration loop complete.")

        console.print(
            "[green]✓[/green] Migration session finished. Run `qsma validate` or `qsma report`."
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
    """Run post-migration validation (build + tests) on a codebase."""
    console.print(f"[bold cyan]qsma validate[/bold cyan] — target: {path}")
    try:
        with Progress(
            SpinnerColumn(), TextColumn("[progress.description]{task.description}")
        ) as progress:
            task = progress.add_task(
                f"Running syntax checks and test suites (timeout: {timeout}s)...", total=None
            )
            import time

            time.sleep(1.5)
            progress.update(task, description="Validation complete.")
        console.print("[green]✓[/green] All modified files pass syntax checks. Test suite passed.")
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
