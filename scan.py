#!/usr/bin/env python3
"""
Simple scan script for Supabase Security Suite
Usage: python3 scan.py /path/to/your/project
"""
import asyncio
import json
import sys
from pathlib import Path
from supabase_security_suite.core.scanner import ScanContext
from supabase_security_suite.scanners import (
    SecretsScanner,
    DockerScanner,
    StaticAnalysisScanner,
    ConfigurationScanner,
    SQLInjectionScanner,
    RLSScanner,
    GraphQLScanner,
)
from supabase_security_suite.reporting.models import ScanResult, ScanMetadata


async def run_scan(target_path: str):
    """Run security scan on the target directory."""
    target = Path(target_path).resolve()
    
    if not target.exists():
        print(f"❌ Error: Directory not found: {target}")
        sys.exit(1)
    
    print(f"🔍 Scanning: {target}")
    print("=" * 70)
    
    context = ScanContext(target_path=target, config=None, verbose=True)
    
    findings = []
    
    # Scanners that work without database/API configuration
    basic_scanners = [
        SecretsScanner(context),
        DockerScanner(context),
        StaticAnalysisScanner(context),
        ConfigurationScanner(context),
        SQLInjectionScanner(context),
    ]
    
    # Scanners that require database/API configuration
    advanced_scanners = [
        (RLSScanner, "RLS Scanner (requires database connection)"),
        (GraphQLScanner, "GraphQL Scanner (requires GraphQL endpoint)"),
    ]
    
    print("\n📦 Running Basic Scanners:")
    print("-" * 70)
    all_scanners = []
    for scanner in basic_scanners:
        try:
            # Some scanners use scan(context), others use scan() with self.context
            if scanner.name in ['static_scanner', 'config_scanner']:
                scanner_findings = await scanner.scan()
            else:
                scanner_findings = await scanner.scan(context)
            findings.extend(scanner_findings)
            all_scanners.append(scanner)
            print(f"✅ {scanner.name}: Found {len(scanner_findings)} issues")
        except Exception as e:
            print(f"⚠️  {scanner.name}: {str(e)[:60]}...")
    
    print("\n📦 Advanced Scanners (require configuration):")
    print("-" * 70)
    for scanner_class, description in advanced_scanners:
        try:
            scanner = scanner_class(context)
            scanner_findings = await scanner.scan(context)
            findings.extend(scanner_findings)
            all_scanners.append(scanner)
            print(f"✅ {scanner.name}: Found {len(scanner_findings)} issues")
        except Exception as e:
            print(f"⏭️  Skipped {description}")
            print(f"   Reason: {str(e)[:60]}...")
    
    if not findings:
        print("\n⚠️  No findings detected. This could mean:")
        print("   • The project is very secure ✅")
        print("   • No scannable files found in directory")
        print("   • RLS/GraphQL scanners need database/API configuration")
    
    # Create result
    result = ScanResult(
        findings=findings,
        metadata=ScanMetadata(
            scan_id="scan_" + str(hash(str(target)))[:8],
            target=str(target),
            duration_seconds=1.0,
            scanners_used=[s.name for s in all_scanners],
        ),
    )
    
    # Save to file in the reports directory (for dashboard)
    reports_dir = Path("supabase_security_reports")
    reports_dir.mkdir(exist_ok=True)
    output_file = reports_dir / "report.json"
    
    with open(output_file, "w") as f:
        json.dump(result.model_dump(mode="json"), f, indent=2)
    
    print("\n" + "=" * 70)
    print(f"🎯 SCAN COMPLETE!")
    print(f"📊 Total Findings: {len(findings)}")
    print(f"🎯 Security Score: {result.score}/100")
    
    if result.statistics.by_severity:
        print("\n📈 By Severity:")
        for severity, count in sorted(
            result.statistics.by_severity.items(),
            key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(
                str(x[0]), 4
            ),
        ):
            print(f"   • {severity}: {count} issues")
    
    print(f"\n✅ Report saved to: {output_file.absolute()}")
    print(f"🌐 View in dashboard: http://localhost:8080")
    print("=" * 70)
    
    return result


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 scan.py /path/to/your/project")
        print("\nExamples:")
        print("  python3 scan.py .")
        print("  python3 scan.py /tmp/demo-supabase-project")
        print("  python3 scan.py ~/my-supabase-app")
        sys.exit(1)
    
    target_path = sys.argv[1]
    asyncio.run(run_scan(target_path))

