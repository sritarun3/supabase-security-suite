"""
Enhanced CLI interface for Supabase Security Suite.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.live import Live
from rich.layout import Layout
from rich.text import Text

from .core.scanner import SupabaseSecurityScanner
from .core.config import SecurityConfig, create_default_config
from .core.finding import FindingSeverity, FindingSource


class SupabaseSecurityCLI:
    """Enhanced CLI interface for the security suite."""
    
    def __init__(self):
        self.console = Console()
        self.config: Optional[SecurityConfig] = None
    
    def run(self, args: Optional[list] = None) -> int:
        """Run the CLI with given arguments."""
        parser = self._create_parser()
        parsed_args = parser.parse_args(args)
        
        try:
            # Load configuration
            if parsed_args.config:
                self.config = SecurityConfig.from_file(parsed_args.config)
            else:
                self.config = create_default_config()
            
            # Override config with CLI arguments
            self._apply_cli_overrides(parsed_args)
            
            # Run the appropriate command
            if parsed_args.command == "scan":
                return self._run_scan(parsed_args)
            elif parsed_args.command == "config":
                return self._run_config(parsed_args)
            elif parsed_args.command == "dashboard":
                return self._run_dashboard(parsed_args)
            else:
                parser.print_help()
                return 1
                
        except Exception as e:
            self.console.print(f"[red]Error: {e}[/]")
            return 1
    
    def _create_parser(self) -> argparse.ArgumentParser:
        """Create the argument parser."""
        parser = argparse.ArgumentParser(
            description="Supabase Security Suite - Comprehensive security scanning for Supabase projects",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  # Basic scan
  supabase-security scan /path/to/project
  
  # Full scan with all features
  supabase-security scan /path/to/project --full --output ./security-report
  
  # CI mode scan
  supabase-security scan /path/to/project --ci --exit-on-critical
  
  # Live monitoring mode
  supabase-security scan /path/to/project --live --watch
  
  # Generate configuration
  supabase-security config generate --output config.json
            """
        )
        
        subparsers = parser.add_subparsers(dest="command", help="Available commands")
        
        # Scan command
        scan_parser = subparsers.add_parser("scan", help="Run security scan")
        scan_parser.add_argument("project_path", help="Path to Supabase project")
        scan_parser.add_argument("--config", help="Configuration file path")
        scan_parser.add_argument("--output", "-o", help="Output directory for reports")
        scan_parser.add_argument("--format", choices=["json", "markdown", "both"], default="both", help="Report format")
        
        # Scan options
        scan_parser.add_argument("--full", action="store_true", help="Run full scan with all features")
        scan_parser.add_argument("--ci", action="store_true", help="CI mode - minimal output, exit codes")
        scan_parser.add_argument("--live", action="store_true", help="Live monitoring mode")
        scan_parser.add_argument("--watch", action="store_true", help="Watch mode - continuous scanning")
        
        # Feature toggles
        scan_parser.add_argument("--no-static", action="store_true", help="Skip static analysis")
        scan_parser.add_argument("--no-secrets", action="store_true", help="Skip secret scanning")
        scan_parser.add_argument("--no-database", action="store_true", help="Skip database checks")
        scan_parser.add_argument("--no-runtime", action="store_true", help="Skip runtime checks")
        scan_parser.add_argument("--no-rls", action="store_true", help="Skip RLS simulation")
        
        # External access
        scan_parser.add_argument("--allow-external", action="store_true", help="Allow external network scans")
        scan_parser.add_argument("--supabase-url", help="Supabase project URL")
        scan_parser.add_argument("--db-url", help="Database connection URL")
        
        # AI and integrations
        scan_parser.add_argument("--ai", action="store_true", help="Enable AI recommendations")
        scan_parser.add_argument("--openai-key", help="OpenAI API key")
        scan_parser.add_argument("--jira", action="store_true", help="Create Jira tickets for findings")
        
        # Exit behavior
        scan_parser.add_argument("--exit-on-critical", action="store_true", help="Exit with error code on critical findings")
        scan_parser.add_argument("--exit-on-high", action="store_true", help="Exit with error code on high+ findings")
        
        # Config command
        config_parser = subparsers.add_parser("config", help="Configuration management")
        config_subparsers = config_parser.add_subparsers(dest="config_action", help="Config actions")
        
        config_subparsers.add_parser("generate", help="Generate default configuration")
        config_subparsers.add_parser("validate", help="Validate configuration file")
        
        # Dashboard command
        dashboard_parser = subparsers.add_parser("dashboard", help="Start web dashboard")
        dashboard_parser.add_argument("--port", type=int, default=8080, help="Dashboard port")
        dashboard_parser.add_argument("--host", default="0.0.0.0", help="Dashboard host")
        
        return parser
    
    def _apply_cli_overrides(self, args) -> None:
        """Apply CLI argument overrides to configuration."""
        if args.command != "scan":
            return
        
        # External access
        if args.allow_external:
            self.config.scan_settings.allow_external_scans = True
        
        if args.supabase_url:
            self.config.supabase_config.project_url = args.supabase_url
        
        if args.db_url:
            self.config.supabase_config.database_url = args.db_url
        
        # AI configuration
        if args.ai or args.openai_key:
            self.config.ai_config.enabled = True
            self.config.scan_settings.enable_ai_recommendations = True
        
        if args.openai_key:
            self.config.ai_config.openai_api_key = args.openai_key
            self.config.ai_config.provider = "openai"
    
    def _run_scan(self, args) -> int:
        """Run security scan."""
        project_path = Path(args.project_path)
        
        if not project_path.exists():
            self.console.print(f"[red]Error: Project path does not exist: {project_path}[/]")
            return 1
        
        # Initialize scanner
        scanner = SupabaseSecurityScanner(str(project_path), self.config)
        
        # Determine scan options
        include_static = not args.no_static
        include_secrets = not args.no_secrets
        include_database = not args.no_database
        include_runtime = not args.no_runtime
        include_rls = not args.no_rls
        
        # CI mode adjustments
        if args.ci:
            self.console.print("[dim]Running in CI mode...[/]")
        
        # Live mode
        if args.live:
            return self._run_live_scan(scanner, args)
        
        # Watch mode
        if args.watch:
            return self._run_watch_mode(scanner, args)
        
        # Single scan
        return self._run_single_scan(scanner, args, include_static, include_secrets, 
                                   include_database, include_runtime, include_rls)
    
    def _run_single_scan(self, scanner, args, include_static, include_secrets, 
                        include_database, include_runtime, include_rls) -> int:
        """Run a single security scan."""
        
        if not args.ci:
            self._print_banner()
        
        # Run scan
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console,
            transient=True
        ) as progress:
            task = progress.add_task("Running security scan...", total=None)
            
            results = scanner.run_full_scan(
                include_static=include_static,
                include_secrets=include_secrets,
                include_database=include_database,
                include_runtime=include_runtime,
                include_rls_simulation=include_rls,
                include_git_history=True,
                use_trufflehog=True
            )
        
        # Display results
        if not args.ci:
            self._display_results(results)
        else:
            self._display_ci_results(results)
        
        # Export reports
        if args.output:
            self._export_reports(scanner, args.output, args.format)
        
        # Check exit conditions
        return self._check_exit_conditions(results, args)
    
    def _run_live_scan(self, scanner, args) -> int:
        """Run live monitoring scan."""
        self.console.print("[bold green]Starting live security monitoring...[/]")
        self.console.print("[dim]Press Ctrl+C to stop[/]")
        
        try:
            while True:
                self.console.clear()
                self._print_banner()
                
                # Run scan
                results = scanner.run_full_scan()
                
                # Display live results
                self._display_live_results(results)
                
                # Wait before next scan
                import time
                time.sleep(30)  # 30 second intervals
                
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Live monitoring stopped.[/]")
            return 0
    
    def _run_watch_mode(self, scanner, args) -> int:
        """Run watch mode for continuous scanning."""
        self.console.print("[bold green]Starting watch mode...[/]")
        self.console.print("[dim]Watching for file changes...[/]")
        
        # This would implement file watching in a real implementation
        # For now, just run a single scan
        return self._run_single_scan(scanner, args, True, True, True, True, True)
    
    def _display_results(self, results: dict) -> None:
        """Display scan results in a formatted way."""
        summary = results["summary"]
        findings = results["findings"]
        
        # Summary panel
        score_color = "green" if summary["security_score"] >= 80 else "yellow" if summary["security_score"] >= 60 else "red"
        
        summary_text = Text()
        summary_text.append(f"Security Score: ", style="bold")
        summary_text.append(f"{summary['security_score']}/100", style=score_color)
        summary_text.append(f"\nRisk Level: {summary['risk_level']}", style="bold")
        summary_text.append(f"\nTotal Findings: {summary['total_findings']}", style="bold")
        
        self.console.print(Panel(summary_text, title="Scan Summary", border_style=score_color))
        
        # Findings table
        if findings:
            table = Table(title="Security Findings", show_header=True, header_style="bold magenta")
            table.add_column("Severity", style="bold", width=10)
            table.add_column("Title", style="bold", width=40)
            table.add_column("Source", width=15)
            table.add_column("File", style="dim", width=30)
            
            for finding in findings[:20]:  # Show first 20 findings
                severity_style = {
                    "CRITICAL": "bold red",
                    "HIGH": "red",
                    "MEDIUM": "yellow",
                    "LOW": "green",
                    "INFO": "blue"
                }.get(finding["severity"], "white")
                
                file_info = finding.get("file", "N/A")
                if finding.get("line"):
                    file_info += f":{finding['line']}"
                
                table.add_row(
                    finding["severity"],
                    finding["title"][:40],
                    finding["source"],
                    file_info[:30],
                    style=severity_style
                )
            
            self.console.print(table)
            
            if len(findings) > 20:
                self.console.print(f"[dim]... and {len(findings) - 20} more findings[/]")
        else:
            self.console.print("[green]No security findings detected![/]")
    
    def _display_ci_results(self, results: dict) -> None:
        """Display results in CI-friendly format."""
        summary = results["summary"]
        findings = results["findings"]
        
        # Simple output for CI
        print(f"Security Score: {summary['security_score']}/100")
        print(f"Risk Level: {summary['risk_level']}")
        print(f"Total Findings: {summary['total_findings']}")
        
        if findings:
            print("\nFindings:")
            for finding in findings:
                print(f"- [{finding['severity']}] {finding['title']} ({finding['source']})")
    
    def _display_live_results(self, results: dict) -> None:
        """Display live monitoring results."""
        summary = results["summary"]
        
        # Create live dashboard layout
        layout = Layout()
        layout.split_column(
            Layout(Panel(f"Security Score: {summary['security_score']}/100", title="Current Status"), size=3),
            Layout(self._create_findings_table(results["findings"]), name="findings")
        )
        
        self.console.print(layout)
    
    def _create_findings_table(self, findings: list) -> Table:
        """Create findings table for live display."""
        table = Table(title="Recent Findings", show_header=True)
        table.add_column("Time", width=8)
        table.add_column("Severity", width=10)
        table.add_column("Title", width=50)
        
        for finding in findings[-10:]:  # Show last 10 findings
            table.add_row(
                "Now",
                finding["severity"],
                finding["title"][:50]
            )
        
        return table
    
    def _export_reports(self, scanner, output_path: str, format: str) -> None:
        """Export scan reports."""
        output_dir = Path(output_path)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        if format in ["json", "both"]:
            scanner.export_report(str(output_dir / "security-report.json"), "json")
            self.console.print(f"[green]JSON report exported to {output_dir / 'security-report.json'}[/]")
        
        if format in ["markdown", "both"]:
            scanner.export_report(str(output_dir / "security-report.md"), "markdown")
            self.console.print(f"[green]Markdown report exported to {output_dir / 'security-report.md'}[/]")
    
    def _check_exit_conditions(self, results: dict, args) -> int:
        """Check exit conditions based on findings."""
        findings = results["findings"]
        
        if args.exit_on_critical:
            critical_findings = [f for f in findings if f["severity"] == "CRITICAL"]
            if critical_findings:
                self.console.print(f"[red]Found {len(critical_findings)} critical findings. Exiting.[/]")
                return 1
        
        if args.exit_on_high:
            high_findings = [f for f in findings if f["severity"] in ["CRITICAL", "HIGH"]]
            if high_findings:
                self.console.print(f"[red]Found {len(high_findings)} high/critical findings. Exiting.[/]")
                return 1
        
        return 0
    
    def _run_config(self, args) -> int:
        """Handle config commands."""
        if args.config_action == "generate":
            config = create_default_config()
            output_path = args.output or "supabase-security-config.json"
            config.save_to_file(output_path)
            self.console.print(f"[green]Configuration generated: {output_path}[/]")
            return 0
        
        elif args.config_action == "validate":
            if not args.config:
                self.console.print("[red]Error: --config required for validate[/]")
                return 1
            
            try:
                config = SecurityConfig.from_file(args.config)
                self.console.print("[green]Configuration is valid[/]")
                return 0
            except Exception as e:
                self.console.print(f"[red]Configuration validation failed: {e}[/]")
                return 1
        
        return 1
    
    def _run_dashboard(self, args) -> int:
        """Start the web dashboard."""
        self.console.print(f"[green]Starting dashboard on {args.host}:{args.port}[/]")
        
        # Import and start dashboard
        try:
            from ..dashboard.server import start_dashboard
            start_dashboard(host=args.host, port=args.port)
        except ImportError:
            self.console.print("[red]Dashboard module not available[/]")
            return 1
        
        return 0
    
    def _print_banner(self) -> None:
        """Print the application banner."""
        banner = """
╔═════════════════════════════════════════════════════════════════════╗
║        S U P A B A S E   S E C U R I T Y   S U I T E   v2.0        ║
║             DevSecOps ▪ Compliance ▪ AI Recommendations            ║
║                    Supabase-Aware Security Scanning                ║
╚═════════════════════════════════════════════════════════════════════╝
        """
        self.console.print(banner, style="bold cyan")


def main():
    """Main entry point for the CLI."""
    cli = SupabaseSecurityCLI()
    sys.exit(cli.run())


if __name__ == "__main__":
    main()
