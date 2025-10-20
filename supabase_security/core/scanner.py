"""
Main Supabase Security Scanner - orchestrates all security checks.
"""

import json
import time
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime

from .config import SecurityConfig
from .finding import SecurityFinding, FindingSeverity, FindingSource, get_compliance_mapping
from ..scanners.static_scanner import StaticScanner
from ..scanners.secret_scanner import SecretScanner
from ..scanners.database_scanner import DatabaseScanner
from ..scanners.runtime_scanner import RuntimeScanner
from ..integrations.supabase_cli import SupabaseCLI
from ..integrations.rls_simulator import RLSSimulator


class SupabaseSecurityScanner:
    """Main security scanner for Supabase projects."""
    
    def __init__(self, project_path: str, config: Optional[SecurityConfig] = None):
        self.project_path = Path(project_path)
        self.config = config or SecurityConfig()
        self.findings: List[SecurityFinding] = []
        self.scan_metadata: Dict[str, Any] = {}
        
        # Initialize scanners
        self.static_scanner = StaticScanner(self.project_path, self.config)
        self.secret_scanner = SecretScanner(self.project_path)
        self.database_scanner = DatabaseScanner(self.config)
        self.runtime_scanner = RuntimeScanner(self.config)
        
        # Initialize Supabase integrations
        self.supabase_cli = SupabaseCLI(self.project_path)
        self.rls_simulator = RLSSimulator()
        
        # Load Supabase configuration
        self.config.load_supabase_config(str(self.project_path))
    
    def run_full_scan(self, 
                     include_static: bool = True,
                     include_secrets: bool = True,
                     include_database: bool = True,
                     include_runtime: bool = True,
                     include_rls_simulation: bool = True,
                     include_git_history: bool = True,
                     use_trufflehog: bool = True) -> Dict[str, Any]:
        """Run a comprehensive security scan."""
        
        scan_start_time = time.time()
        self.scan_metadata = {
            "scan_start": datetime.now().isoformat(),
            "project_path": str(self.project_path),
            "config": self.config.to_dict()
        }
        
        print("🔒 Starting Supabase Security Suite Scan")
        print("=" * 50)
        
        # Static analysis
        if include_static:
            print("\n📁 Running static analysis...")
            static_findings = self.static_scanner.scan_project()
            self.findings.extend(static_findings)
            print(f"   Found {len(static_findings)} static analysis findings")
        
        # Secret detection
        if include_secrets:
            print("\n🔐 Scanning for secrets...")
            secret_findings = self.secret_scanner.scan_project(
                include_git_history=include_git_history,
                use_trufflehog=use_trufflehog
            )
            self.findings.extend(secret_findings)
            print(f"   Found {len(secret_findings)} secret findings")
        
        # Supabase CLI analysis
        print("\n🏗️  Analyzing Supabase project structure...")
        supabase_findings = self._analyze_supabase_project()
        self.findings.extend(supabase_findings)
        print(f"   Found {len(supabase_findings)} Supabase-specific findings")
        
        # RLS simulation
        if include_rls_simulation:
            print("\n🛡️  Analyzing RLS policies...")
            rls_findings = self._analyze_rls_policies()
            self.findings.extend(rls_findings)
            print(f"   Found {len(rls_findings)} RLS policy findings")
        
        # Database security checks
        if include_database and self.config.supabase_config.database_url:
            print("\n🗄️  Running database security checks...")
            db_findings = self.database_scanner.scan_database()
            self.findings.extend(db_findings)
            print(f"   Found {len(db_findings)} database findings")
        
        # Runtime security checks
        if include_runtime and self.config.supabase_config.project_url:
            print("\n🌐 Running runtime security checks...")
            runtime_findings = self.runtime_scanner.scan_endpoints()
            self.findings.extend(runtime_findings)
            print(f"   Found {len(runtime_findings)} runtime findings")
        
        # Calculate final score and metadata
        scan_end_time = time.time()
        self.scan_metadata.update({
            "scan_end": datetime.now().isoformat(),
            "scan_duration": scan_end_time - scan_start_time,
            "total_findings": len(self.findings)
        })
        
        # Generate summary
        summary = self._generate_summary()
        
        print(f"\n✅ Scan completed in {scan_end_time - scan_start_time:.2f} seconds")
        print(f"📊 Total findings: {len(self.findings)}")
        print(f"🎯 Security score: {summary['security_score']}/100")
        
        return {
            "findings": [f.to_dict() for f in self.findings],
            "summary": summary,
            "metadata": self.scan_metadata
        }
    
    def _analyze_supabase_project(self) -> List[SecurityFinding]:
        """Analyze Supabase project structure and configuration."""
        findings = []
        
        try:
            # Validate project structure
            validation = self.supabase_cli.validate_project_structure()
            
            if not validation["valid"]:
                findings.append(SecurityFinding(
                    id="supabase:invalid_structure",
                    title="Invalid Supabase project structure",
                    severity=FindingSeverity.HIGH,
                    confidence="HIGH",
                    description="Project is missing required Supabase directories or files",
                    impact="Invalid project structure may cause deployment issues",
                    recommendation="Run 'supabase init' to initialize proper project structure",
                    source=FindingSource.STATIC,
                    metadata={"validation_issues": validation["issues"]}
                ))
            
            # Get security recommendations
            recommendations = self.supabase_cli.get_security_recommendations()
            
            for rec in recommendations:
                severity_map = {
                    "HIGH": FindingSeverity.HIGH,
                    "MEDIUM": FindingSeverity.MEDIUM,
                    "LOW": FindingSeverity.LOW
                }
                
                findings.append(SecurityFinding(
                    id=f"supabase:{rec['type']}:{rec['title'].lower().replace(' ', '_')}",
                    title=rec["title"],
                    severity=severity_map.get(rec["severity"], FindingSeverity.MEDIUM),
                    confidence="HIGH",
                    description=rec["description"],
                    impact=rec.get("impact", "Supabase-specific security issue"),
                    recommendation=rec["recommendation"],
                    source=FindingSource.STATIC,
                    metadata={"recommendation_type": rec["type"]}
                ))
            
        except Exception as e:
            findings.append(SecurityFinding(
                id="supabase:analysis_error",
                title="Supabase project analysis failed",
                severity=FindingSeverity.MEDIUM,
                confidence="LOW",
                description=f"Error analyzing Supabase project: {e}",
                impact="Unable to perform Supabase-specific security checks",
                recommendation="Check project structure and Supabase CLI installation",
                source=FindingSource.STATIC,
                metadata={"error": str(e)}
            ))
        
        return findings
    
    def _analyze_rls_policies(self) -> List[SecurityFinding]:
        """Analyze RLS policies using the simulator."""
        findings = []
        
        try:
            # Get migrations and extract policies
            migrations = self.supabase_cli.get_migrations()
            
            for migration in migrations:
                try:
                    migration_path = Path(migration["path"])
                    if migration_path.exists():
                        content = migration_path.read_text()
                        policies = self.rls_simulator.load_policies_from_sql(content)
                        
                        # Add table information
                        tables = self.supabase_cli.get_tables_with_rls()
                        for table in tables:
                            table_info = type('TableInfo', (), {
                                'name': table['name'],
                                'schema': 'public',
                                'columns': [],
                                'rls_enabled': table['rls_enabled'],
                                'policies': []
                            })()
                            self.rls_simulator.add_table(table_info)
                
                except Exception as e:
                    print(f"Error processing migration {migration['filename']}: {e}")
            
            # Generate RLS findings
            rls_findings = self.rls_simulator.get_security_findings()
            
            for finding_data in rls_findings:
                findings.append(SecurityFinding(
                    id=finding_data["id"],
                    title=finding_data["title"],
                    severity=FindingSeverity(finding_data["severity"]),
                    confidence="HIGH",
                    description=finding_data["description"],
                    impact=finding_data["impact"],
                    recommendation=finding_data["recommendation"],
                    source=FindingSource.RLS_SIMULATOR,
                    metadata=finding_data.get("metadata", {})
                ))
            
        except Exception as e:
            findings.append(SecurityFinding(
                id="rls:analysis_error",
                title="RLS policy analysis failed",
                severity=FindingSeverity.MEDIUM,
                confidence="LOW",
                description=f"Error analyzing RLS policies: {e}",
                impact="Unable to perform RLS security analysis",
                recommendation="Check migration files and RLS policy definitions",
                source=FindingSource.RLS_SIMULATOR,
                metadata={"error": str(e)}
            ))
        
        return findings
    
    def _generate_summary(self) -> Dict[str, Any]:
        """Generate scan summary and statistics."""
        if not self.findings:
            return {
                "security_score": 100,
                "total_findings": 0,
                "by_severity": {},
                "by_source": {},
                "risk_level": "LOW"
            }
        
        # Calculate security score
        total_risk = sum(f.get_risk_score() for f in self.findings)
        security_score = max(0, 100 - total_risk)
        
        # Count by severity
        by_severity = {}
        for severity in FindingSeverity:
            count = len([f for f in self.findings if f.severity == severity])
            if count > 0:
                by_severity[severity.value] = count
        
        # Count by source
        by_source = {}
        for source in FindingSource:
            count = len([f for f in self.findings if f.source == source])
            if count > 0:
                by_source[source.value] = count
        
        # Determine risk level
        critical_count = len([f for f in self.findings if f.severity == FindingSeverity.CRITICAL])
        high_count = len([f for f in self.findings if f.severity == FindingSeverity.HIGH])
        
        if critical_count > 0:
            risk_level = "CRITICAL"
        elif high_count > 2:
            risk_level = "HIGH"
        elif high_count > 0 or len(self.findings) > 10:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        return {
            "security_score": security_score,
            "total_findings": len(self.findings),
            "by_severity": by_severity,
            "by_source": by_source,
            "risk_level": risk_level,
            "critical_count": critical_count,
            "high_count": high_count
        }
    
    def export_report(self, output_path: str, format: str = "json") -> None:
        """Export scan results to file."""
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        scan_results = {
            "findings": [f.to_dict() for f in self.findings],
            "summary": self._generate_summary(),
            "metadata": self.scan_metadata
        }
        
        if format.lower() == "json":
            with open(output_file, 'w') as f:
                json.dump(scan_results, f, indent=2)
        
        elif format.lower() == "markdown":
            self._export_markdown_report(output_file, scan_results)
        
        else:
            raise ValueError(f"Unsupported export format: {format}")
    
    def _export_markdown_report(self, output_file: Path, scan_results: Dict[str, Any]) -> None:
        """Export report in Markdown format."""
        summary = scan_results["summary"]
        findings = scan_results["findings"]
        
        md_content = [
            "# Supabase Security Suite Report",
            "",
            f"**Security Score:** {summary['security_score']}/100",
            f"**Risk Level:** {summary['risk_level']}",
            f"**Total Findings:** {summary['total_findings']}",
            f"**Scan Date:** {self.scan_metadata.get('scan_start', 'Unknown')}",
            "",
            "## Summary",
            "",
            f"- **Critical:** {summary.get('critical_count', 0)}",
            f"- **High:** {summary.get('high_count', 0)}",
            f"- **Medium:** {summary.get('by_severity', {}).get('MEDIUM', 0)}",
            f"- **Low:** {summary.get('by_severity', {}).get('LOW', 0)}",
            f"- **Info:** {summary.get('by_severity', {}).get('INFO', 0)}",
            "",
            "## Findings",
            ""
        ]
        
        if not findings:
            md_content.append("- No security findings detected.")
        else:
            for finding in findings:
                md_content.extend([
                    f"### {finding['title']}",
                    f"- **Severity:** {finding['severity']}",
                    f"- **Source:** {finding['source']}",
                    f"- **File:** {finding.get('file', 'N/A')}",
                    f"- **Line:** {finding.get('line', 'N/A')}",
                    f"- **Description:** {finding['description']}",
                    f"- **Impact:** {finding['impact']}",
                    f"- **Recommendation:** {finding['recommendation']}",
                    ""
                ])
        
        with open(output_file, 'w') as f:
            f.write('\n'.join(md_content))
    
    def get_critical_findings(self) -> List[SecurityFinding]:
        """Get only critical and high severity findings."""
        return [f for f in self.findings if f.severity in [FindingSeverity.CRITICAL, FindingSeverity.HIGH]]
    
    def get_findings_by_source(self, source: FindingSource) -> List[SecurityFinding]:
        """Get findings from a specific source."""
        return [f for f in self.findings if f.source == source]
    
    def get_findings_by_severity(self, severity: FindingSeverity) -> List[SecurityFinding]:
        """Get findings of a specific severity."""
        return [f for f in self.findings if f.severity == severity]
