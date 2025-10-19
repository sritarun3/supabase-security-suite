"""
Unit tests for scanners.rls_scanner module.
"""

import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from supabase_security_suite.scanners.rls_scanner import RLSScanner
from supabase_security_suite.core.scanner import ScanContext
from supabase_security_suite.reporting.models import Severity, FindingCategory
from supabase_security_suite.core.config import RLSScannerConfig


class TestRLSScanner:
    """Tests for RLSScanner."""
    
    def test_scanner_initialization(self, scan_context):
        """Test RLS scanner initialization."""
        scanner = RLSScanner(scan_context)
        
        assert scanner.name == "rls_scanner"
        assert "rls" in scanner.description.lower() or "row level security" in scanner.description.lower()
        assert scanner.category == "rls"
    
    @pytest.mark.asyncio
    async def test_scan_no_database(self, scan_context):
        """Test scanning with no database connection."""
        # No db_connection set
        scanner = RLSScanner(scan_context)
        findings = await scanner.scan(scan_context)
        
        # Should handle gracefully
        assert isinstance(findings, list)
    
    @pytest.mark.asyncio
    async def test_scan_tables_without_rls(self, scan_context):
        """Test detecting tables without RLS enabled."""
        # Mock database connection
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[
            {"table_schema": "public", "table_name": "users", "rls_enabled": False},
            {"table_schema": "public", "table_name": "posts", "rls_enabled": False},
        ])
        scan_context.db_connection = mock_conn
        
        scanner = RLSScanner(scan_context)
        findings = await scanner.scan(scan_context)
        
        # Should detect tables without RLS
        assert len(findings) >= 2
        rls_findings = [f for f in findings if "rls" in f.title.lower()]
        assert len(rls_findings) >= 2
        
        # Check finding properties
        if rls_findings:
            finding = rls_findings[0]
            assert finding.severity in [Severity.HIGH, Severity.CRITICAL]
            assert finding.category == FindingCategory.RLS
    
    @pytest.mark.asyncio
    async def test_scan_tables_with_rls(self, scan_context):
        """Test tables with RLS enabled."""
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[
            {"table_schema": "public", "table_name": "users", "rls_enabled": True},
        ])
        scan_context.db_connection = mock_conn
        
        scanner = RLSScanner(scan_context)
        findings = await scanner.scan(scan_context)
        
        # Should not flag tables with RLS enabled
        rls_disabled_findings = [f for f in findings if "not enabled" in f.description.lower()]
        assert len(rls_disabled_findings) == 0
    
    @pytest.mark.asyncio
    async def test_scan_missing_policies(self, scan_context):
        """Test detecting tables with RLS but no policies."""
        mock_conn = AsyncMock()
        
        # Mock fetch to return different results based on query
        async def mock_fetch(query, *args):
            if "rowsecurity" in query.lower():
                # RLS enabled
                return [{"table_schema": "public", "table_name": "users", "rls_enabled": True}]
            elif "pg_policies" in query.lower():
                # No policies
                return []
            return []
        
        mock_conn.fetch = AsyncMock(side_effect=mock_fetch)
        scan_context.db_connection = mock_conn
        
        scanner = RLSScanner(scan_context)
        findings = await scanner.scan(scan_context)
        
        # Should detect RLS enabled but no policies
        policy_findings = [f for f in findings if "policy" in f.title.lower() or "policy" in f.description.lower()]
        assert len(policy_findings) > 0
    
    @pytest.mark.asyncio
    async def test_scan_asymmetric_policies(self, scan_context):
        """Test detecting asymmetric RLS policies."""
        scan_context.config.scanners.rls.check_asymmetric_policies = True
        
        mock_conn = AsyncMock()
        
        async def mock_fetch(query, *args):
            if "rowsecurity" in query.lower():
                return [{"table_schema": "public", "table_name": "posts", "rls_enabled": True}]
            elif "pg_policies" in query.lower():
                # Only SELECT policy, no INSERT/UPDATE/DELETE
                return [
                    {"table_name": "posts", "policy_name": "select_policy", "cmd": "SELECT"},
                ]
            return []
        
        mock_conn.fetch = AsyncMock(side_effect=mock_fetch)
        scan_context.db_connection = mock_conn
        
        scanner = RLSScanner(scan_context)
        findings = await scanner.scan(scan_context)
        
        # Should detect asymmetric policies
        asymmetric_findings = [f for f in findings if "asymmetric" in f.description.lower() or "missing" in f.description.lower()]
        assert len(asymmetric_findings) > 0
    
    @pytest.mark.asyncio
    async def test_scan_public_tables(self, scan_context):
        """Test detecting publicly accessible tables."""
        mock_conn = AsyncMock()
        
        async def mock_fetch(query, *args):
            if "rowsecurity" in query.lower():
                return [{"table_schema": "public", "table_name": "public_data", "rls_enabled": True}]
            elif "pg_policies" in query.lower():
                # Policy that allows all users
                return [
                    {
                        "table_name": "public_data",
                        "policy_name": "allow_all",
                        "cmd": "SELECT",
                        "qual": "true",  # No restrictions
                    },
                ]
            return []
        
        mock_conn.fetch = AsyncMock(side_effect=mock_fetch)
        scan_context.db_connection = mock_conn
        
        scanner = RLSScanner(scan_context)
        findings = await scanner.scan(scan_context)
        
        # Should flag overly permissive policies
        permissive_findings = [f for f in findings if "permissive" in f.description.lower() or "public" in f.description.lower()]
        assert len(permissive_findings) > 0
    
    @pytest.mark.asyncio
    async def test_scan_check_indexes(self, scan_context):
        """Test checking for indexes on RLS columns."""
        scan_context.config.scanners.rls.check_indexes = True
        
        mock_conn = AsyncMock()
        
        async def mock_fetch(query, *args):
            if "rowsecurity" in query.lower():
                return [{"table_schema": "public", "table_name": "users", "rls_enabled": True}]
            elif "pg_policies" in query.lower():
                return [
                    {
                        "table_name": "users",
                        "policy_name": "user_policy",
                        "cmd": "SELECT",
                        "qual": "user_id = auth.uid()",
                    },
                ]
            elif "pg_indexes" in query.lower():
                # No index on user_id
                return []
            return []
        
        mock_conn.fetch = AsyncMock(side_effect=mock_fetch)
        scan_context.db_connection = mock_conn
        
        scanner = RLSScanner(scan_context)
        findings = await scanner.scan(scan_context)
        
        # Should recommend indexes for performance
        index_findings = [f for f in findings if "index" in f.description.lower() or "performance" in f.description.lower()]
        assert len(index_findings) > 0
    
    @pytest.mark.asyncio
    async def test_scan_system_tables_excluded(self, scan_context):
        """Test that system tables are excluded."""
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[
            {"table_schema": "pg_catalog", "table_name": "pg_class", "rls_enabled": False},
            {"table_schema": "information_schema", "table_name": "tables", "rls_enabled": False},
            {"table_schema": "public", "table_name": "users", "rls_enabled": False},
        ])
        scan_context.db_connection = mock_conn
        
        scanner = RLSScanner(scan_context)
        findings = await scanner.scan(scan_context)
        
        # Should not flag system tables
        system_findings = [f for f in findings if f.location and (
            "pg_catalog" in f.location.table or
            "information_schema" in f.location.table
        )]
        assert len(system_findings) == 0
    
    @pytest.mark.asyncio
    async def test_scan_recommendation_provided(self, scan_context):
        """Test that recommendations are provided."""
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[
            {"table_schema": "public", "table_name": "users", "rls_enabled": False},
        ])
        scan_context.db_connection = mock_conn
        
        scanner = RLSScanner(scan_context)
        findings = await scanner.scan(scan_context)
        
        assert len(findings) > 0
        for finding in findings:
            # Each finding should have a recommendation
            assert finding.recommendation is not None
            assert len(finding.recommendation) > 0
    
    @pytest.mark.asyncio
    async def test_scan_with_connection_error(self, scan_context):
        """Test handling database connection errors."""
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(side_effect=Exception("Connection failed"))
        scan_context.db_connection = mock_conn
        
        scanner = RLSScanner(scan_context)
        findings = await scanner.scan(scan_context)
        
        # Should handle error gracefully
        assert isinstance(findings, list)
    
    @pytest.mark.asyncio
    async def test_finding_details(self, scan_context):
        """Test that findings have all required details."""
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[
            {"table_schema": "public", "table_name": "sensitive_data", "rls_enabled": False},
        ])
        scan_context.db_connection = mock_conn
        
        scanner = RLSScanner(scan_context)
        findings = await scanner.scan(scan_context)
        
        assert len(findings) > 0
        finding = findings[0]
        
        # Check all required fields
        assert finding.id is not None
        assert finding.title is not None
        assert finding.description is not None
        assert finding.severity is not None
        assert finding.category == FindingCategory.RLS
        assert finding.recommendation is not None
        
        # Check location information
        if finding.location:
            assert finding.location.table is not None
    
    @pytest.mark.asyncio
    async def test_severity_levels(self, scan_context):
        """Test that appropriate severity levels are assigned."""
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[
            {"table_schema": "public", "table_name": "users", "rls_enabled": False},
            {"table_schema": "public", "table_name": "audit_log", "rls_enabled": False},
        ])
        scan_context.db_connection = mock_conn
        
        scanner = RLSScanner(scan_context)
        findings = await scanner.scan(scan_context)
        
        # Tables with user data should be high/critical severity
        user_table_findings = [f for f in findings if f.location and "users" in f.location.table]
        if user_table_findings:
            assert user_table_findings[0].severity in [Severity.HIGH, Severity.CRITICAL]
    
    @pytest.mark.asyncio
    async def test_complex_policy_analysis(self, scan_context):
        """Test analyzing complex RLS policies."""
        mock_conn = AsyncMock()
        
        async def mock_fetch(query, *args):
            if "rowsecurity" in query.lower():
                return [{"table_schema": "public", "table_name": "documents", "rls_enabled": True}]
            elif "pg_policies" in query.lower():
                return [
                    {
                        "table_name": "documents",
                        "policy_name": "user_documents",
                        "cmd": "SELECT",
                        "qual": "owner_id = current_user_id() OR is_public = true",
                    },
                    {
                        "table_name": "documents",
                        "policy_name": "insert_own",
                        "cmd": "INSERT",
                        "qual": "owner_id = current_user_id()",
                    },
                ]
            return []
        
        mock_conn.fetch = AsyncMock(side_effect=mock_fetch)
        scan_context.db_connection = mock_conn
        
        scanner = RLSScanner(scan_context)
        findings = await scanner.scan(scan_context)
        
        # Should analyze policies even if they exist
        assert isinstance(findings, list)

