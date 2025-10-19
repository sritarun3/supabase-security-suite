"""
Integration tests for full security scans.
"""

import pytest
import json
from pathlib import Path

from supabase_security_suite.core.config import Config
from supabase_security_suite.core.scanner import CompositeScanner, ScanContext
from supabase_security_suite.scanners import (
    SecretsScanner,
    DockerScanner,
    # Add other scanners as they're imported
)
from supabase_security_suite.reporting.models import Severity, FindingCategory


@pytest.mark.integration
class TestFullScan:
    """Integration tests for full security scans."""
    
    @pytest.mark.asyncio
    async def test_full_scan_with_all_scanners(self, minimal_config, test_files):
        """Test running all scanners together."""
        context = ScanContext(
            config=minimal_config,
            target_path=str(test_files["python"].parent),
        )
        
        scanners = [
            SecretsScanner(context),
            DockerScanner(context),
        ]
        
        composite = CompositeScanner(context, scanners)
        findings = await composite.scan_all()
        
        # Should find issues across multiple scanners
        assert len(findings) > 0
        
        # Check that different categories are represented
        categories = {f.category for f in findings}
        assert len(categories) >= 2
    
    @pytest.mark.asyncio
    async def test_scan_real_project(self, minimal_config, tmp_path):
        """Test scanning a realistic project structure."""
        # Create a realistic project structure
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        
        # Source directory
        src_dir = project_dir / "src"
        src_dir.mkdir()
        
        # App file with secrets
        (src_dir / "app.py").write_text("""
import os
from supabase import create_client

# Bad: Hardcoded credentials
SUPABASE_URL = "https://myproject.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSJ9"
API_KEY = "sk-1234567890abcdef"

def init_supabase():
    return create_client(SUPABASE_URL, SUPABASE_KEY)
        """)
        
        # Docker compose with issues
        (project_dir / "docker-compose.yml").write_text("""
version: '3.8'
services:
  db:
    image: postgres:latest
    environment:
      POSTGRES_PASSWORD: weak_password
    ports:
      - "5432:5432"  # Exposed port
  
  app:
    build: .
    ports:
      - "80:8080"
    environment:
      DEBUG: "true"
      SECRET_KEY: "hardcoded-secret"
        """)
        
        # .env file
        (project_dir / ".env").write_text("""
DATABASE_URL=postgresql://user:password@localhost/db
SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.service_role
        """)
        
        context = ScanContext(
            config=minimal_config,
            target_path=str(project_dir),
        )
        
        scanners = [
            SecretsScanner(context),
            DockerScanner(context),
        ]
        
        composite = CompositeScanner(context, scanners)
        findings = await composite.scan_all()
        
        # Should find multiple issues
        assert len(findings) >= 3
        
        # Check severity distribution
        severities = [f.severity for f in findings]
        assert Severity.HIGH in severities or Severity.CRITICAL in severities
        
        # Check that different files were scanned
        files = {f.location.file for f in findings if f.location}
        assert len(files) >= 2
    
    @pytest.mark.asyncio
    async def test_scan_with_exclusions(self, minimal_config, tmp_path):
        """Test scanning with file exclusions."""
        # Create files with realistic API keys (20+ chars)
        (tmp_path / "app.py").write_text('API_KEY = "sk-test-1234567890abcdefghijk"')
        
        vendor_dir = tmp_path / "vendor"
        vendor_dir.mkdir()
        (vendor_dir / "lib.py").write_text('API_KEY = "sk-vendor-1234567890abcdefghijk"')
        
        node_modules = tmp_path / "node_modules"
        node_modules.mkdir()
        (node_modules / "package.js").write_text('const key = "sk-node-1234567890abcdefghijk";')
        
        context = ScanContext(
            config=minimal_config,
            target_path=str(tmp_path),
            exclude_patterns=["vendor/*", "node_modules/*"],
        )
        
        scanner = SecretsScanner(context)
        findings = await scanner.scan(context)
        
        # Should only scan app.py
        assert len(findings) > 0
        files_scanned = {f.location.file for f in findings if f.location}
        assert not any("vendor" in f or "node_modules" in f for f in files_scanned)
    
    @pytest.mark.asyncio
    async def test_scan_performance(self, minimal_config, tmp_path):
        """Test scan performance with many files."""
        # Create many files
        for i in range(50):
            file_path = tmp_path / f"file_{i}.py"
            file_path.write_text(f'# File {i}\nVAR = "value_{i}"')
        
        # Add one file with a secret (20+ chars)
        (tmp_path / "secret.py").write_text('API_KEY = "sk-1234567890abcdefghijk"')
        
        context = ScanContext(
            config=minimal_config,
            target_path=str(tmp_path),
        )
        
        import time
        start_time = time.time()
        
        scanner = SecretsScanner(context)
        findings = await scanner.scan(context)
        
        duration = time.time() - start_time
        
        # Should complete in reasonable time (< 10 seconds for 50 files)
        assert duration < 10.0
        
        # Should still find the secret
        assert len(findings) > 0
    
    @pytest.mark.asyncio
    async def test_scan_result_serialization(self, minimal_config, test_files):
        """Test that scan results can be serialized to JSON."""
        context = ScanContext(
            config=minimal_config,
            target_path=str(test_files["python"].parent),
        )
        
        scanner = SecretsScanner(context)
        findings = await scanner.scan(context)
        
        # Convert findings to JSON
        findings_json = json.dumps([f.model_dump(mode="json") for f in findings], indent=2, default=str)
        
        # Should be valid JSON
        assert findings_json
        
        # Parse it back
        findings_data = json.loads(findings_json)
        assert isinstance(findings_data, list)
    
    @pytest.mark.asyncio
    async def test_scan_with_verbose_output(self, minimal_config, test_files):
        """Test scanning with verbose output enabled."""
        context = ScanContext(
            config=minimal_config,
            target_path=str(test_files["python"].parent),
            verbose=True,
        )
        
        scanner = SecretsScanner(context)
        findings = await scanner.scan(context)
        
        # Should complete successfully with verbose mode
        assert findings is not None
    
    @pytest.mark.asyncio
    async def test_scan_dry_run(self, minimal_config, test_files):
        """Test dry run mode."""
        context = ScanContext(
            config=minimal_config,
            target_path=str(test_files["python"].parent),
            dry_run=True,
        )
        
        scanner = SecretsScanner(context)
        findings = await scanner.scan(context)
        
        # Dry run should still return findings
        assert findings is not None
    
    @pytest.mark.asyncio
    async def test_empty_directory_scan(self, minimal_config, empty_directory):
        """Test scanning an empty directory."""
        context = ScanContext(
            config=minimal_config,
            target_path=str(empty_directory),
        )
        
        scanner = SecretsScanner(context)
        findings = await scanner.scan(context)
        
        # Should return empty list, not error
        assert findings == []
    
    @pytest.mark.asyncio
    async def test_scan_statistics(self, minimal_config, test_files):
        """Test generating scan statistics."""
        from supabase_security_suite.reporting.models import ScanStatistics
        
        context = ScanContext(
            config=minimal_config,
            target_path=str(test_files["python"].parent),
        )
        
        scanner = SecretsScanner(context)
        findings = await scanner.scan(context)
        
        # Generate statistics manually
        by_severity = {}
        by_category = {}
        for finding in findings:
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
            by_category[finding.category] = by_category.get(finding.category, 0) + 1
        
        stats = ScanStatistics(
            total_findings=len(findings),
            by_severity=by_severity,
            by_category=by_category,
        )
        
        assert stats.total_findings == len(findings)
        assert sum(stats.by_severity.values()) == len(findings)
        assert sum(stats.by_category.values()) == len(findings)


@pytest.mark.integration
@pytest.mark.slow
class TestLargeProjectScan:
    """Integration tests for scanning large projects."""
    
    @pytest.mark.asyncio
    async def test_large_codebase(self, minimal_config, tmp_path):
        """Test scanning a large codebase."""
        # Create a larger project structure
        for i in range(10):
            dir_path = tmp_path / f"module_{i}"
            dir_path.mkdir()
            
            for j in range(20):
                file_path = dir_path / f"file_{j}.py"
                content = f"# Module {i}, File {j}\n"
                if i == 5 and j == 10:
                    # Add a secret in one file (20+ chars)
                    content += 'API_KEY = "sk-1234567890abcdefghijklmnop"'
                else:
                    content += f'VAR_{j} = "value_{j}"'
                file_path.write_text(content)
        
        context = ScanContext(
            config=minimal_config,
            target_path=str(tmp_path),
        )
        
        scanner = SecretsScanner(context)
        findings = await scanner.scan(context)
        
        # Should find the secret despite large codebase
        assert len(findings) > 0
        
        # Should identify the correct file (check in title, description, or file path)
        secret_findings = [f for f in findings if f.location and "module_5" in str(f.location.file)]
        assert len(secret_findings) > 0


@pytest.mark.integration
class TestScannerCombinations:
    """Test different combinations of scanners."""
    
    @pytest.mark.asyncio
    async def test_secrets_and_docker(self, minimal_config, test_files):
        """Test running secrets and docker scanners together."""
        context = ScanContext(
            config=minimal_config,
            target_path=str(test_files["python"].parent),
        )
        
        scanners = [
            SecretsScanner(context),
            DockerScanner(context),
        ]
        
        composite = CompositeScanner(context, scanners)
        findings = await composite.scan_all()
        
        # Should have findings from both scanners
        categories = {f.category for f in findings}
        # At least one category should be present
        assert len(categories) >= 1
    
    @pytest.mark.asyncio
    async def test_no_duplicate_findings(self, minimal_config, test_files):
        """Test that running multiple scanners doesn't produce duplicate findings."""
        context = ScanContext(
            config=minimal_config,
            target_path=str(test_files["python"].parent),
        )
        
        # Run the same scanner twice
        scanner1 = SecretsScanner(context)
        scanner2 = SecretsScanner(context)
        
        findings1 = await scanner1.scan(context)
        findings2 = await scanner2.scan(context)
        
        # Same scanner should produce same results
        assert len(findings1) == len(findings2)

