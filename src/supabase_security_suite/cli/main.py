"""
Main CLI application using Typer.
"""

import asyncio
import json
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.table import Table

from supabase_security_suite import __version__
from supabase_security_suite.core import Config, ScanContext, load_config
from supabase_security_suite.core.utils import get_environment_info
from supabase_security_suite.reporting import ScanMetadata, ScanResult

# Create Typer app
app = typer.Typer(
    name="suite",
    help="Supabase Security Suite - Comprehensive security scanner for Supabase projects",
    add_completion=False,
)

console = Console()


def version_callback(value: bool):
    """Show version and exit."""
    if value:
        console.print(f"Supabase Security Suite v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        None,
        "--version",
        "-v",
        callback=version_callback,
        is_eager=True,
        help="Show version and exit",
    ),
):
    """
    Supabase Security Suite CLI.

    Run security scans, test RLS policies, and generate compliance reports.
    """
    pass


@app.command()
def scan(
    target: Path = typer.Argument(
        Path.cwd(),
        help="Target directory to scan",
        exists=True,
        file_okay=False,
        dir_okay=True,
        resolve_path=True,
    ),
    config_file: Optional[Path] = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to configuration file",
        exists=True,
    ),
    scanners: Optional[str] = typer.Option(
        None,
        "--scanners",
        "-s",
        help="Comma-separated list of scanners to run (default: all)",
    ),
    output_format: str = typer.Option(
        "json",
        "--format",
        "-f",
        help="Output format: json, markdown, pdf, sarif",
    ),
    output_file: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Save results to file",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        help="Enable verbose output",
    ),
):
    """
    Run security scanners on the target project.

    Example:
        suite scan /path/to/project --config config.json --output report.json
    """
    console.print("[bold blue]🔍 Supabase Security Scan[/bold blue]")
    console.print(f"Target: {target}")

    # Load configuration
    try:
        if config_file:
            console.print(f"Loading config from: {config_file}")
            config = load_config(config_file)
        else:
            console.print("[yellow]No config file provided, using defaults[/yellow]")
            # For now, we'll need at least database connection info
            console.print(
                "[red]Error: Configuration file required for database access[/red]"
            )
            console.print(
                "Create a config file with: [bold]suite init-config[/bold]"
            )
            raise typer.Exit(code=1)

        config.target = target
        config.output_format = output_format
        config.output_file = output_file
        config.verbose = verbose

    except FileNotFoundError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]Error loading config: {e}[/red]")
        raise typer.Exit(code=1)

    # Run the scan
    try:
        result = asyncio.run(_run_scan(config, scanners))

        # Display results
        _display_results(result)

        # Save to file if requested
        if output_file:
            _save_results(result, output_file, output_format)
            console.print(f"[green]✓[/green] Results saved to: {output_file}")

        # Exit with error code if critical findings found
        if result.has_critical_findings():
            console.print(
                "[red]⚠ Critical findings detected! Review the report.[/red]"
            )
            raise typer.Exit(code=1)

    except KeyboardInterrupt:
        console.print("\n[yellow]Scan cancelled by user[/yellow]")
        raise typer.Exit(code=130)
    except Exception as e:
        console.print(f"[red]Scan failed: {e}[/red]")
        if verbose:
            console.print_exception()
        raise typer.Exit(code=1)


@app.command()
def init_config(
    output_file: Path = typer.Option(
        Path("config.json"),
        "--output",
        "-o",
        help="Path for the config file",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Overwrite existing file",
    ),
):
    """
    Create a default configuration file.

    Example:
        suite init-config --output my-config.json
    """
    if output_file.exists() and not force:
        console.print(f"[yellow]File already exists: {output_file}[/yellow]")
        console.print("Use --force to overwrite")
        raise typer.Exit(code=1)

    try:
        from supabase_security_suite.core.config import create_default_config

        create_default_config(output_file)
        console.print(f"[green]✓[/green] Configuration file created: {output_file}")
        console.print(
            "[yellow]⚠[/yellow] Please edit the file to add your credentials"
        )

    except Exception as e:
        console.print(f"[red]Error creating config: {e}[/red]")
        raise typer.Exit(code=1)


@app.command()
def ci(
    config_file: Path = typer.Option(
        ...,
        "--config",
        "-c",
        help="Path to configuration file",
        exists=True,
    ),
    fail_on: str = typer.Option(
        "critical",
        "--fail-on",
        help="Fail if findings with severity: critical, high, medium, low",
    ),
    sarif: bool = typer.Option(
        False,
        "--sarif",
        help="Output SARIF format for GitHub Code Scanning",
    ),
):
    """
    Run in CI mode (non-interactive, machine-readable output).

    Example:
        suite ci --config config.json --fail-on high --sarif > security.sarif
    """
    # This is a simplified version - full implementation would come later
    console.print("[bold]Running in CI mode...[/bold]")
    console.print("[yellow]CI mode not fully implemented yet[/yellow]")
    console.print("Use 'suite scan' for now")
    raise typer.Exit(code=1)


# Helper functions

async def _run_scan(config: Config, scanner_names: Optional[str]) -> ScanResult:
    """Run the actual scan asynchronously."""
    start_time = time.time()

    # Create scan context
    context = ScanContext(
        config=config,
        target_path=config.target,
    )

    # Initialize database pool
    await context.initialize_db_pool()

    try:
        # Import and initialize scanners
        # For now, this is a placeholder - actual scanners will be added in Phase 3
        from supabase_security_suite.core import CompositeScanner

        scanners = []
        # TODO: Load actual scanner implementations

        if not scanners:
            console.print(
                "[yellow]No scanners available yet - Phase 3 will add scanner implementations[/yellow]"
            )

        # Create composite scanner and run
        composite = CompositeScanner(context, scanners)
        findings = await composite.scan_all()

        # Deduplicate findings if enabled in config
        from supabase_security_suite.reporting.deduplicator import FindingDeduplicator

        deduplicator = FindingDeduplicator()
        original_count = len(findings)
        
        # Check if deduplication is enabled (default: True)
        enable_dedup = getattr(config, 'enable_deduplication', True)
        if enable_dedup and findings:
            findings = deduplicator.deduplicate(findings)
            if config.verbose:
                stats = deduplicator.get_deduplication_stats(
                    [None] * original_count,  # Just for count
                    findings
                )
                console.print(
                    f"[dim]Deduplication: {stats['original_count']} → {stats['deduplicated_count']} "
                    f"(-{stats['reduction_pct']}%)[/dim]"
                )

        # Create scan result
        duration = time.time() - start_time

        metadata = ScanMetadata(
            scan_id=context.scan_id,
            timestamp=datetime.utcnow(),
            duration_seconds=duration,
            target=str(config.target),
            scanners_used=[s.name for s in scanners],
            environment=get_environment_info(),
        )

        result = ScanResult(
            findings=findings,
            metadata=metadata,
        )

        # Update statistics and score
        for finding in findings:
            result.add_finding(finding)

        return result

    finally:
        # Clean up
        await context.close_db_pool()


def _display_results(result: ScanResult) -> None:
    """Display scan results in the console."""
    console.print("\n[bold]📊 Scan Results[/bold]")
    console.print(f"Scan ID: {result.metadata.scan_id}")
    console.print(f"Duration: {result.metadata.duration_seconds:.2f}s")
    console.print(f"Security Score: [bold]{result.score}/100[/bold]")

    # Summary table
    table = Table(title="Summary")
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")

    for severity, count in result.statistics.by_severity.items():
        color = {
            "CRITICAL": "red",
            "HIGH": "orange1",
            "MEDIUM": "yellow",
            "LOW": "blue",
            "INFO": "green",
        }.get(severity.value, "white")

        table.add_row(severity.value, f"[{color}]{count}[/{color}]")

    console.print(table)

    # Findings details
    if result.findings:
        console.print(f"\n[bold]🔍 Findings ({len(result.findings)} total)[/bold]")
        for i, finding in enumerate(result.findings[:10], 1):  # Show first 10
            severity_color = {
                "CRITICAL": "red",
                "HIGH": "orange1",
                "MEDIUM": "yellow",
                "LOW": "blue",
                "INFO": "green",
            }.get(finding.severity.value, "white")

            console.print(
                f"{i}. [{severity_color}]{finding.severity.value}[/{severity_color}] - {finding.title}"
            )

        if len(result.findings) > 10:
            console.print(f"... and {len(result.findings) - 10} more")


def _save_results(result: ScanResult, output_file: Path, format: str) -> None:
    """Save scan results to a file."""
    if format == "json":
        with open(output_file, "w") as f:
            json.dump(result.model_dump(), f, indent=2, default=str)
    elif format == "markdown":
        # TODO: Implement markdown export
        console.print("[yellow]Markdown export not implemented yet[/yellow]")
    elif format == "pdf":
        # TODO: Implement PDF export
        console.print("[yellow]PDF export not implemented yet[/yellow]")
    elif format == "sarif":
        # TODO: Implement SARIF export
        console.print("[yellow]SARIF export not implemented yet[/yellow]")
    else:
        console.print(f"[red]Unknown format: {format}[/red]")


if __name__ == "__main__":
    app()

