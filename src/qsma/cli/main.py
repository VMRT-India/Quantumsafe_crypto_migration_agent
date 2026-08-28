"""
qsma.cli.main
=============
Top-level Click group that wires together all CLI sub-commands.

This module is intentionally thin — it delegates all business logic to
the domain modules under src/qsma/.

Entry point: `qsma` (defined in pyproject.toml [project.scripts])
"""

import click
from rich.console import Console

console = Console()

CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"]}


@click.group(context_settings=CONTEXT_SETTINGS)
@click.version_option(version="0.1.0", prog_name="qsma")
def cli() -> None:
    """Quantum-Safe Crypto Migration Agent.

    Analyze, detect, and migrate quantum-vulnerable cryptography in a codebase.

    \b
    Typical workflow:
        qsma scan  <path>          — detect crypto findings
        qsma report <path>         — display findings report
        qsma migrate <path>        — interactively migrate selected findings
        qsma validate <path>       — validate post-migration correctness
    """


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--format", "fmt", type=click.Choice(["text", "json", "markdown"]), default="text")
@click.option("--output", "-o", type=click.Path(), default=None, help="Write report to file.")
def scan(path: str, fmt: str, output: str | None) -> None:
    """Scan a codebase for quantum-vulnerable cryptographic usage."""
    console.print(f"[bold cyan]qsma scan[/bold cyan] — target: {path}  [dim](stub)[/dim]")
    console.print("[yellow]Module not yet implemented — see PROJECT_CONTEXT.md[/yellow]")


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--findings", type=click.Path(), default=None, help="Load findings from JSON file.")
def report(path: str, findings: str | None) -> None:
    """Display a formatted findings report for a previously scanned codebase."""
    console.print(f"[bold cyan]qsma report[/bold cyan] — target: {path}  [dim](stub)[/dim]")
    console.print("[yellow]Module not yet implemented — see PROJECT_CONTEXT.md[/yellow]")


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--finding-id", multiple=True, help="Migrate specific finding ID(s) only.")
@click.option("--dry-run", is_flag=True, default=False, help="Show proposed changes without applying.")
@click.option("--auto", is_flag=True, default=False, help="Non-interactive: migrate all HIGH findings.")
def migrate(path: str, finding_id: tuple[str, ...], dry_run: bool, auto: bool) -> None:
    """Interactively select and apply quantum-safe migrations."""
    console.print(f"[bold cyan]qsma migrate[/bold cyan] — target: {path}  [dim](stub)[/dim]")
    console.print("[yellow]Module not yet implemented — see PROJECT_CONTEXT.md[/yellow]")


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--timeout", default=120, show_default=True, help="Validation timeout (seconds).")
def validate(path: str, timeout: int) -> None:
    """Run post-migration validation (build + tests) on a codebase."""
    console.print(f"[bold cyan]qsma validate[/bold cyan] — target: {path}  [dim](stub)[/dim]")
    console.print("[yellow]Module not yet implemented — see PROJECT_CONTEXT.md[/yellow]")


if __name__ == "__main__":
    cli()
