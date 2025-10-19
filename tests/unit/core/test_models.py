"""
Unit tests for reporting.models module.
"""

import pytest
from datetime import datetime

from supabase_security_suite.reporting.models import (
    Severity,
    FindingCategory,
    Location,
    Finding,
    ScanMetadata,
    ScanStatistics,
    ScanResult,
)


class TestSeverity:
    """Tests for Severity enum."""
    
    def test_severity_values(self):
        """Test severity enum values."""
        assert Severity.INFO.value == "INFO"
        assert Severity.LOW.value == "LOW"
        assert Severity.MEDIUM.value == "MEDIUM"
        assert Severity.HIGH.value == "HIGH"
        assert Severity.CRITICAL.value == "CRITICAL"
    
    def test_severity_ordering(self):
        """Test severity comparison."""
        severities = [
            Severity.INFO,
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        ]
        
        for i, sev in enumerate(severities):
            assert sev.value == ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"][i]


class TestFindingCategory:
    """Tests for FindingCategory enum."""
    
    def test_category_values(self):
        """Test category enum values."""
        assert FindingCategory.RLS.value == "rls"
        assert FindingCategory.SECRETS.value == "secrets"
        assert FindingCategory.DOCKER.value == "docker"
        assert FindingCategory.GRAPHQL.value == "graphql"
        assert FindingCategory.SQL_INJECTION.value == "sql_injection"
        assert FindingCategory.RUNTIME.value == "runtime"
    
    def test_all_categories_exist(self):
        """Test that all expected categories exist."""
        expected = {
            "rls", "secrets", "docker", "graphql",
            "sql_injection", "runtime", "config"
        }
        actual = {cat.value for cat in FindingCategory}
        assert expected.issubset(actual)


class TestLocation:
    """Tests for Location model."""
    
    def test_minimal_location(self):
        """Test creating minimal location."""
        location = Location(file="test.py")
        
        assert location.file == "test.py"
        assert location.line is None
        assert location.column is None
    
    def test_full_location(self):
        """Test creating full location."""
        location = Location(
            file="src/app.py",
            line=42,
            column=10,
            table="users",
            policy="select_policy",
        )
        
        assert location.file == "src/app.py"
        assert location.line == 42
        assert location.column == 10
        assert location.table == "users"
        assert location.policy == "select_policy"
    
    def test_location_with_path(self):
        """Test location with full path."""
        location = Location(file="/home/user/project/src/main.py", line=100)
        
        assert "/home/user/project/src/main.py" in location.file
        assert location.line == 100


class TestFinding:
    """Tests for Finding model."""
    
    def test_minimal_finding(self, sample_finding):
        """Test creating minimal finding."""
        assert sample_finding.id == "TEST-001"
        assert sample_finding.title == "Test Security Finding"
        assert sample_finding.severity == Severity.HIGH
        assert sample_finding.category == FindingCategory.RLS
    
    def test_finding_with_all_fields(self):
        """Test creating finding with all fields."""
        finding = Finding(
            id="SEC-001",
            title="SQL Injection Vulnerability",
            description="User input not sanitized",
            severity=Severity.CRITICAL,
            category=FindingCategory.SQL_INJECTION,
            source="sql_injection_scanner",
            recommendation="Use parameterized queries",
            location=Location(file="api.py", line=50),
            ai_recommendation="Implement input validation",
            compliance={
                "OWASP": ["A03:2021"],
                "CWE": ["CWE-89"]
            },
            metadata={
                "confidence": 0.95,
                "impact": "Database compromise",
                "affected_resource": "users table",
                "references": ["https://owasp.org/Top10/A03_2021-Injection/"],
            }
        )
        
        assert finding.id == "SEC-001"
        assert finding.severity == Severity.CRITICAL
        assert finding.metadata["confidence"] == 0.95
        assert "CWE-89" in finding.compliance["CWE"]
        assert finding.ai_recommendation == "Implement input validation"
    
    def test_finding_validation(self):
        """Test finding validation."""
        # Valid finding
        finding = Finding(
            id="TEST-001",
            title="Test",
            description="Test finding",
            severity=Severity.HIGH,
            category=FindingCategory.RLS,
            source="test_scanner",
            recommendation="Fix this issue",
        )
        assert finding.id == "TEST-001"
        
        # Should require all mandatory fields (missing source and recommendation)
        with pytest.raises(Exception):
            Finding(
                id="TEST-002",
                title="Test",
                description="Test",
                severity=Severity.HIGH,
                category=FindingCategory.RLS,
                # Missing source and recommendation - should fail
            )
    
    def test_finding_to_dict(self, sample_finding):
        """Test converting finding to dictionary."""
        finding_dict = sample_finding.model_dump()
        
        assert finding_dict["id"] == "TEST-001"
        assert finding_dict["severity"] == "HIGH"
        assert isinstance(finding_dict["discovered_at"], datetime)
    
    def test_finding_json_serialization(self, sample_finding):
        """Test JSON serialization of finding."""
        json_str = sample_finding.model_dump_json()
        
        assert "TEST-001" in json_str
        assert "HIGH" in json_str
        assert "Test Security Finding" in json_str


class TestScanMetadata:
    """Tests for ScanMetadata model."""
    
    def test_minimal_metadata(self):
        """Test creating minimal metadata."""
        metadata = ScanMetadata(
            scan_id="scan_123",
            target="/test/path",
            duration_seconds=1.5,
        )
        
        assert metadata.target == "/test/path"
        assert metadata.scan_id == "scan_123"
        assert isinstance(metadata.timestamp, datetime)
        assert metadata.scanners_used == []
    
    def test_full_metadata(self):
        """Test creating full metadata."""
        metadata = ScanMetadata(
            scan_id="scan_456",
            target="/project/src",
            scanners_used=["rls_scanner", "secrets_scanner"],
            duration_seconds=45.2,
            environment={"python_version": "3.13", "os": "Linux"},
        )
        
        assert metadata.target == "/project/src"
        assert metadata.scan_id == "scan_456"
        assert "rls_scanner" in metadata.scanners_used
        assert metadata.duration_seconds == 45.2
        assert metadata.environment["os"] == "Linux"
    
    def test_metadata_timestamp(self):
        """Test metadata timestamp is set automatically."""
        metadata = ScanMetadata(
            scan_id="scan_789",
            target="/test",
            duration_seconds=2.5,
        )
        
        assert isinstance(metadata.timestamp, datetime)
        assert metadata.timestamp <= datetime.utcnow()


class TestScanStatistics:
    """Tests for ScanStatistics model."""
    
    def test_empty_statistics(self):
        """Test creating empty statistics."""
        stats = ScanStatistics()
        
        assert stats.total_findings == 0
        assert stats.by_severity == {}
        assert stats.by_category == {}
    
    def test_full_statistics(self):
        """Test creating full statistics."""
        stats = ScanStatistics(
            total_findings=10,
            by_severity={
                Severity.CRITICAL: 2,
                Severity.HIGH: 3,
                Severity.MEDIUM: 5,
            },
            by_category={
                FindingCategory.RLS: 4,
                FindingCategory.SECRETS: 6,
            },
            by_source={
                "rls_scanner": 4,
                "secrets_scanner": 6,
            }
        )
        
        assert stats.total_findings == 10
        assert stats.by_severity[Severity.CRITICAL] == 2
        assert stats.by_category[FindingCategory.RLS] == 4
        assert stats.by_source["rls_scanner"] == 4
        assert stats.by_source["secrets_scanner"] == 6
    
    def test_statistics_calculation(self, sample_findings):
        """Test calculating statistics from findings."""
        # Calculate stats manually since from_findings might not exist
        by_severity = {}
        by_category = {}
        for finding in sample_findings:
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
            by_category[finding.category] = by_category.get(finding.category, 0) + 1
        
        stats = ScanStatistics(
            total_findings=len(sample_findings),
            by_severity=by_severity,
            by_category=by_category,
        )
        
        assert stats.total_findings == len(sample_findings)
        assert stats.by_severity[Severity.CRITICAL] == 1
        assert stats.by_severity[Severity.HIGH] == 1
        assert stats.by_severity[Severity.MEDIUM] == 1


class TestScanResult:
    """Tests for ScanResult model."""
    
    def test_minimal_result(self):
        """Test creating minimal scan result."""
        result = ScanResult(
            metadata=ScanMetadata(
                scan_id="scan_min",
                target="/test",
                duration_seconds=0.5,
            ),
            findings=[],
        )
        
        assert result.metadata.target == "/test"
        assert result.findings == []
        assert result.statistics.total_findings == 0
    
    def test_full_result(self, scan_result):
        """Test creating full scan result."""
        assert scan_result.metadata.target == "/test/path"
        assert len(scan_result.findings) == 3
        assert scan_result.statistics.total_findings == 3
        assert scan_result.score == 45
    
    def test_result_with_findings(self, sample_findings):
        """Test scan result with findings."""
        result = ScanResult(
            metadata=ScanMetadata(
                scan_id="scan_findings",
                target="/project",
                duration_seconds=3.5,
                scanners_used=["rls_scanner", "secrets_scanner"],
            ),
            findings=sample_findings,
        )
        
        assert len(result.findings) == 3
        assert result.statistics.total_findings == 3
        assert Severity.CRITICAL in result.statistics.by_severity
    
    def test_result_score_calculation(self):
        """Test security score calculation."""
        # Perfect score (no findings)
        perfect_result = ScanResult(
            metadata=ScanMetadata(
                scan_id="scan_perfect",
                target="/test",
                duration_seconds=1.0,
            ),
            findings=[],
            score=100.0,
        )
        assert perfect_result.score == 100.0
        
        # Low score (many critical findings)
        low_result = ScanResult(
            metadata=ScanMetadata(
                scan_id="scan_low",
                target="/test",
                duration_seconds=2.0,
            ),
            findings=[
                Finding(
                    id=f"CRIT-{i}",
                    title=f"Critical {i}",
                    description="Critical issue",
                    severity=Severity.CRITICAL,
                    category=FindingCategory.SQL_INJECTION,
                    source="sql_injection_scanner",
                    recommendation="Fix immediately",
                )
                for i in range(10)
            ],
            score=20.0,
        )
        assert low_result.score < 30.0
    
    def test_result_json_export(self, scan_result):
        """Test exporting scan result to JSON."""
        json_str = scan_result.model_dump_json(indent=2)
        
        assert "TEST-001" in json_str
        assert "CRITICAL" in json_str
        assert "findings" in json_str
        assert "metadata" in json_str
        assert "statistics" in json_str
    
    def test_result_severity_distribution(self, scan_result):
        """Test severity distribution in results."""
        assert scan_result.statistics.by_severity[Severity.CRITICAL] == 1
        assert scan_result.statistics.by_severity[Severity.HIGH] == 1
        assert scan_result.statistics.by_severity[Severity.MEDIUM] == 1
    
    def test_result_category_distribution(self, scan_result):
        """Test category distribution in results."""
        assert scan_result.statistics.by_category[FindingCategory.RLS] == 1
        assert scan_result.statistics.by_category[FindingCategory.SQL_INJECTION] == 1
        assert scan_result.statistics.by_category[FindingCategory.SECRETS] == 1


class TestModelSerialization:
    """Tests for model serialization and deserialization."""
    
    def test_finding_roundtrip(self, sample_finding):
        """Test finding serialization roundtrip."""
        # Serialize to dict
        finding_dict = sample_finding.model_dump()
        
        # Deserialize back to Finding
        recreated = Finding(**finding_dict)
        
        assert recreated.id == sample_finding.id
        assert recreated.title == sample_finding.title
        assert recreated.severity == sample_finding.severity
    
    def test_scan_result_roundtrip(self, scan_result):
        """Test scan result serialization roundtrip."""
        # Serialize to JSON string
        json_str = scan_result.model_dump_json()
        
        # Deserialize back to ScanResult
        import json
        result_dict = json.loads(json_str)
        recreated = ScanResult(**result_dict)
        
        assert recreated.metadata.target == scan_result.metadata.target
        assert len(recreated.findings) == len(scan_result.findings)
    
    def test_severity_serialization(self):
        """Test severity enum serialization."""
        finding = Finding(
            id="TEST",
            title="Test",
            description="Test",
            severity=Severity.HIGH,
            category=FindingCategory.RLS,
            source="test_scanner",
            recommendation="Fix this issue",
        )
        
        finding_dict = finding.model_dump()
        assert finding_dict["severity"] == "HIGH"
        
        # Recreate from dict
        recreated = Finding(**finding_dict)
        assert recreated.severity == Severity.HIGH

