"""
Tests for the FindingDeduplicator.
"""

import pytest
from supabase_security_suite.reporting.deduplicator import FindingDeduplicator
from supabase_security_suite.reporting.models import Finding, Severity, FindingCategory, Location


class TestFindingDeduplicator:
    """Test cases for FindingDeduplicator."""

    def test_no_duplicates(self):
        """Test deduplication with no duplicates."""
        deduplicator = FindingDeduplicator()
        
        findings = [
            Finding(
                id="1",
                title="Issue 1",
                description="Description 1",
                severity=Severity.HIGH,
                category=FindingCategory.RLS,
                source="test",
                recommendation="Fix it",
                location=Location(file="file1.py", line=10),
            ),
            Finding(
                id="2",
                title="Issue 2",
                description="Description 2",
                severity=Severity.MEDIUM,
                category=FindingCategory.SECRETS,
                source="test",
                recommendation="Fix it",
                location=Location(file="file2.py", line=20),
            ),
        ]
        
        result = deduplicator.deduplicate(findings)
        assert len(result) == 2

    def test_duplicates_same_file(self):
        """Test deduplication with duplicates in same file."""
        deduplicator = FindingDeduplicator()
        
        findings = [
            Finding(
                id="1",
                title="HTTP endpoint present",
                description="HTTP URL found",
                severity=Severity.MEDIUM,
                category=FindingCategory.CONFIGURATION,
                source="config_scanner",
                recommendation="Use HTTPS",
                location=Location(file=".env", line=10),
            ),
            Finding(
                id="2",
                title="HTTP endpoint present",
                description="HTTP URL found",
                severity=Severity.MEDIUM,
                category=FindingCategory.CONFIGURATION,
                source="config_scanner",
                recommendation="Use HTTPS",
                location=Location(file=".env", line=15),
            ),
            Finding(
                id="3",
                title="HTTP endpoint present",
                description="HTTP URL found",
                severity=Severity.MEDIUM,
                category=FindingCategory.CONFIGURATION,
                source="config_scanner",
                recommendation="Use HTTPS",
                location=Location(file=".env", line=20),
            ),
        ]
        
        result = deduplicator.deduplicate(findings)
        
        # Should merge to 1 finding
        assert len(result) == 1
        
        # Should have metadata with all lines
        assert result[0].metadata.get("all_lines") == [10, 15, 20]
        assert result[0].metadata.get("occurrence_count") == 3
        
        # Description should indicate multiple locations
        assert "3 locations" in result[0].description

    def test_duplicates_different_files(self):
        """Test that same issue in different files are NOT merged."""
        deduplicator = FindingDeduplicator()
        
        findings = [
            Finding(
                id="1",
                title="Weak JWT Secret",
                description="JWT secret is weak",
                severity=Severity.HIGH,
                category=FindingCategory.CONFIGURATION,
                source="config_scanner",
                recommendation="Use stronger secret",
                location=Location(file=".env.dev", line=5),
            ),
            Finding(
                id="2",
                title="Weak JWT Secret",
                description="JWT secret is weak",
                severity=Severity.HIGH,
                category=FindingCategory.CONFIGURATION,
                source="config_scanner",
                recommendation="Use stronger secret",
                location=Location(file=".env.prod", line=5),
            ),
        ]
        
        result = deduplicator.deduplicate(findings)
        
        # Should NOT merge (different files)
        assert len(result) == 2

    def test_empty_findings(self):
        """Test deduplication with empty list."""
        deduplicator = FindingDeduplicator()
        result = deduplicator.deduplicate([])
        assert len(result) == 0

    def test_get_deduplication_stats(self):
        """Test deduplication statistics."""
        deduplicator = FindingDeduplicator()
        
        original = [Finding(
            id=str(i),
            title="Issue",
            description="Desc",
            severity=Severity.MEDIUM,
            category=FindingCategory.SECRETS,
            source="test",
            recommendation="Fix",
            location=Location(file="file.py", line=i),
        ) for i in range(10)]
        
        deduplicated = [original[0]]  # Simulated deduplication
        
        stats = deduplicator.get_deduplication_stats(original, deduplicated)
        
        assert stats["original_count"] == 10
        assert stats["deduplicated_count"] == 1
        assert stats["removed_count"] == 9
        assert stats["reduction_pct"] == 90

    def test_findings_without_location(self):
        """Test deduplication with findings that have no location."""
        deduplicator = FindingDeduplicator()
        
        findings = [
            Finding(
                id="1",
                title="RLS disabled",
                description="Table has no RLS",
                severity=Severity.CRITICAL,
                category=FindingCategory.RLS,
                source="rls_scanner",
                recommendation="Enable RLS",
                location=None,
            ),
            Finding(
                id="2",
                title="RLS disabled",
                description="Table has no RLS",
                severity=Severity.CRITICAL,
                category=FindingCategory.RLS,
                source="rls_scanner",
                recommendation="Enable RLS",
                location=None,
            ),
        ]
        
        result = deduplicator.deduplicate(findings)
        
        # Should merge findings without location
        assert len(result) == 1

