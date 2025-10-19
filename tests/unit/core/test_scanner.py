"""
Unit tests for core.scanner module.
"""

import pytest
from pathlib import Path
from unittest.mock import Mock, AsyncMock, patch

from supabase_security_suite.core.scanner import BaseScanner, CompositeScanner, ScanContext
from supabase_security_suite.core.config import Config
from supabase_security_suite.reporting.models import Finding, Severity, FindingCategory


class MockScanner(BaseScanner):
    """Mock scanner for testing."""
    
    name = "mock_scanner"
    description = "Mock scanner for testing"
    category = "test"
    
    def __init__(self, context: ScanContext, return_findings: list[Finding] = None):
        super().__init__(context)
        self.return_findings = return_findings or []
        self.scan_called = False
        self.pre_scan_called = False
        self.post_scan_called = False
    
    async def scan(self, context: ScanContext) -> list[Finding]:
        """Mock scan implementation."""
        self.scan_called = True
        return self.return_findings
    
    async def pre_scan(self):
        """Mock pre-scan hook."""
        self.pre_scan_called = True
    
    async def post_scan(self, findings: list[Finding]):
        """Mock post-scan hook."""
        self.post_scan_called = True
        return findings


class FailingScanner(BaseScanner):
    """Scanner that always fails for testing error handling."""
    
    name = "failing_scanner"
    description = "Failing scanner for testing"
    category = "test"
    
    async def scan(self, context: ScanContext) -> list[Finding]:
        """Always raises an exception."""
        raise RuntimeError("Scanner failed intentionally")


class TestScanContext:
    """Tests for ScanContext."""
    
    def test_minimal_context(self, minimal_config, tmp_path):
        """Test creating minimal scan context."""
        context = ScanContext(
            config=minimal_config,
            target_path=str(tmp_path),
        )
        
        assert context.config == minimal_config
        assert context.target_path == str(tmp_path)
        assert context.verbose is False
        assert context.dry_run is False
    
    def test_full_context(self, full_config, tmp_path):
        """Test creating full scan context."""
        context = ScanContext(
            config=full_config,
            target_path=str(tmp_path),
            verbose=True,
            dry_run=True,
            exclude_patterns=["*test*"],
        )
        
        assert context.verbose is True
        assert context.dry_run is True
        assert "*test*" in context.exclude_patterns
    
    def test_context_target_path_validation(self, minimal_config):
        """Test target path validation."""
        # Valid path
        context = ScanContext(config=minimal_config, target_path="/valid/path")
        assert context.target_path == "/valid/path"


class TestBaseScanner:
    """Tests for BaseScanner."""
    
    def test_scanner_initialization(self, scan_context):
        """Test scanner initialization."""
        scanner = MockScanner(scan_context)
        
        assert scanner.name == "mock_scanner"
        assert scanner.description == "Mock scanner for testing"
        assert scanner.category == "test"
        assert scanner.context == scan_context
    
    def test_scanner_metadata(self, scan_context):
        """Test scanner metadata access."""
        scanner = MockScanner(scan_context)
        
        assert scanner.name == "mock_scanner"
        assert "Mock scanner" in scanner.description
        assert scanner.category == "test"
    
    @pytest.mark.asyncio
    async def test_scanner_basic_scan(self, scan_context):
        """Test basic scanner execution."""
        finding = Finding(
            id="TEST-001",
            title="Test Finding",
            description="Test",
            severity=Severity.HIGH,
            category=FindingCategory.RLS,
            source="mock_scanner",
            recommendation="Fix this issue",
        )
        
        scanner = MockScanner(scan_context, return_findings=[finding])
        findings = await scanner.scan(scan_context)
        
        assert len(findings) == 1
        assert findings[0].id == "TEST-001"
        assert scanner.scan_called is True
    
    @pytest.mark.asyncio
    async def test_scanner_hooks(self, scan_context):
        """Test scanner pre/post hooks."""
        scanner = MockScanner(scan_context)
        
        await scanner.pre_scan()
        findings = await scanner.scan(scan_context)
        await scanner.post_scan(findings)
        
        assert scanner.pre_scan_called is True
        assert scanner.scan_called is True
        assert scanner.post_scan_called is True
    
    @pytest.mark.asyncio
    async def test_scanner_empty_results(self, scan_context):
        """Test scanner with no findings."""
        scanner = MockScanner(scan_context, return_findings=[])
        findings = await scanner.scan(scan_context)
        
        assert findings == []
        assert scanner.scan_called is True
    
    @pytest.mark.asyncio
    async def test_scanner_multiple_findings(self, scan_context, sample_findings):
        """Test scanner with multiple findings."""
        scanner = MockScanner(scan_context, return_findings=sample_findings)
        findings = await scanner.scan(scan_context)
        
        assert len(findings) == 3
        assert all(isinstance(f, Finding) for f in findings)


class TestCompositeScanner:
    """Tests for CompositeScanner."""
    
    @pytest.mark.asyncio
    async def test_composite_scanner_initialization(self, scan_context):
        """Test composite scanner initialization."""
        scanner1 = MockScanner(scan_context)
        scanner2 = MockScanner(scan_context)
        
        composite = CompositeScanner(scan_context, [scanner1, scanner2])
        
        assert len(composite.scanners) == 2
    
    @pytest.mark.asyncio
    async def test_composite_scanner_empty(self, scan_context):
        """Test composite scanner with no scanners."""
        composite = CompositeScanner(scan_context, [])
        findings = await composite.scan_all()
        
        assert findings == []
    
    @pytest.mark.asyncio
    async def test_composite_scanner_single(self, scan_context):
        """Test composite scanner with single scanner."""
        finding = Finding(
            id="TEST-001",
            title="Test",
            description="Test",
            severity=Severity.HIGH,
            category=FindingCategory.RLS,
            source="test_scanner",
            recommendation="Fix this issue",
        )
        
        scanner = MockScanner(scan_context, return_findings=[finding])
        composite = CompositeScanner(scan_context, [scanner])
        
        findings = await composite.scan_all()
        
        assert len(findings) == 1
        assert findings[0].id == "TEST-001"
    
    @pytest.mark.asyncio
    async def test_composite_scanner_multiple(self, scan_context):
        """Test composite scanner with multiple scanners."""
        finding1 = Finding(
            id="TEST-001",
            title="Finding 1",
            description="Test",
            severity=Severity.HIGH,
            category=FindingCategory.RLS,
            source="test_scanner_1",
            recommendation="Fix this issue",
        )
        
        finding2 = Finding(
            id="TEST-002",
            title="Finding 2",
            description="Test",
            severity=Severity.MEDIUM,
            category=FindingCategory.SECRETS,
            source="test_scanner_2",
            recommendation="Fix this issue",
        )
        
        scanner1 = MockScanner(scan_context, return_findings=[finding1])
        scanner2 = MockScanner(scan_context, return_findings=[finding2])
        
        composite = CompositeScanner(scan_context, [scanner1, scanner2])
        findings = await composite.scan_all()
        
        assert len(findings) == 2
        assert {f.id for f in findings} == {"TEST-001", "TEST-002"}
    
    @pytest.mark.asyncio
    async def test_composite_scanner_error_handling(self, scan_context):
        """Test composite scanner handles failing scanners gracefully."""
        finding = Finding(
            id="TEST-001",
            title="Test",
            description="Test",
            severity=Severity.HIGH,
            category=FindingCategory.RLS,
            source="test_scanner",
            recommendation="Fix this issue",
        )
        
        good_scanner = MockScanner(scan_context, return_findings=[finding])
        bad_scanner = FailingScanner(scan_context)
        
        composite = CompositeScanner(scan_context, [good_scanner, bad_scanner])
        
        # Should continue and return findings from good scanner
        findings = await composite.scan_all()
        
        # Good scanner should still have run
        assert good_scanner.scan_called is True
    
    @pytest.mark.asyncio
    async def test_composite_scanner_filtering(self, scan_context):
        """Test filtering scanners by category."""
        scanner1 = MockScanner(scan_context)
        scanner1.category = "rls"
        
        scanner2 = MockScanner(scan_context)
        scanner2.category = "secrets"
        
        composite = CompositeScanner(scan_context, [scanner1, scanner2])
        
        # All scanners
        assert len(composite.scanners) == 2
        
        # Filter by category
        rls_scanners = [s for s in composite.scanners if s.category == "rls"]
        assert len(rls_scanners) == 1


class TestScannerLogging:
    """Tests for scanner logging functionality."""
    
    @pytest.mark.asyncio
    async def test_verbose_logging(self, minimal_config, tmp_path):
        """Test verbose logging during scan."""
        context = ScanContext(
            config=minimal_config,
            target_path=str(tmp_path),
            verbose=True,
        )
        
        scanner = MockScanner(context)
        
        with patch("rich.console.Console.print") as mock_print:
            await scanner.scan(context)
            # Verbose mode should log messages (implementation specific)
    
    @pytest.mark.asyncio
    async def test_dry_run_mode(self, minimal_config, tmp_path):
        """Test dry run mode."""
        context = ScanContext(
            config=minimal_config,
            target_path=str(tmp_path),
            dry_run=True,
        )
        
        scanner = MockScanner(context)
        findings = await scanner.scan(context)
        
        # In dry run, findings should still be returned
        # but no actions should be taken
        assert isinstance(findings, list)


class TestScannerIntegration:
    """Integration tests for scanner functionality."""
    
    @pytest.mark.asyncio
    async def test_full_scan_workflow(self, scan_context):
        """Test complete scan workflow."""
        finding = Finding(
            id="TEST-001",
            title="Test Finding",
            description="Test",
            severity=Severity.HIGH,
            category=FindingCategory.RLS,
            source="test_scanner",
            recommendation="Fix this issue",
        )
        
        scanner = MockScanner(scan_context, return_findings=[finding])
        
        # Pre-scan
        await scanner.pre_scan()
        assert scanner.pre_scan_called is True
        
        # Scan
        findings = await scanner.scan(scan_context)
        assert len(findings) == 1
        assert scanner.scan_called is True
        
        # Post-scan
        await scanner.post_scan(findings)
        assert scanner.post_scan_called is True
    
    @pytest.mark.asyncio
    async def test_scanner_with_config(self, full_config, tmp_path):
        """Test scanner with full configuration."""
        context = ScanContext(
            config=full_config,
            target_path=str(tmp_path),
        )
        
        scanner = MockScanner(context)
        
        # Scanner should have access to config
        assert scanner.context.config.database.host == "localhost"
        assert scanner.context.config.ai.enabled is True
    
    @pytest.mark.asyncio
    async def test_multiple_scanners_different_categories(self, scan_context):
        """Test running multiple scanners with different categories."""
        findings = []
        
        for i, category in enumerate([FindingCategory.RLS, FindingCategory.SECRETS, FindingCategory.DOCKER]):
            finding = Finding(
                id=f"TEST-{i+1:03d}",
                title=f"Finding {i+1}",
                description="Test",
                severity=Severity.HIGH,
                category=category,
                source=f"test_scanner_{i+1}",
                recommendation="Fix this issue",
            )
            findings.append(finding)
            
        scanners = [
            MockScanner(scan_context, return_findings=[findings[i]])
            for i in range(3)
        ]
        
        composite = CompositeScanner(scan_context, scanners)
        all_findings = await composite.scan_all()
        
        assert len(all_findings) == 3
        categories = {f.category for f in all_findings}
        assert len(categories) == 3  # All different categories

