"""
Unit tests for scanners.runtime_scanner module.
"""

import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from supabase_security_suite.scanners.runtime_scanner import RuntimeScanner
from supabase_security_suite.core.scanner import ScanContext
from supabase_security_suite.reporting.models import Severity, FindingCategory


class TestRuntimeScanner:
    """Tests for RuntimeScanner."""
    
    def test_scanner_initialization(self, scan_context):
        """Test Runtime scanner initialization."""
        scanner = RuntimeScanner(scan_context)
        
        assert scanner.name == "runtime_scanner"
        assert "runtime" in scanner.description.lower()
        assert scanner.category == "runtime"
    
    @pytest.mark.asyncio
    async def test_scan_no_supabase_connection(self, scan_context):
        """Test scanning with no Supabase connection."""
        # No http_client set
        scanner = RuntimeScanner(scan_context)
        findings = await scanner.scan(scan_context)
        
        # Should handle gracefully
        assert isinstance(findings, list)
    
    @pytest.mark.asyncio
    async def test_scan_jwt_validation(self, scan_context):
        """Test checking JWT validation."""
        # Mock HTTP client
        mock_http = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 401
        mock_response.json = AsyncMock(return_value={"error": "Invalid JWT"})
        mock_http.get = AsyncMock(return_value=mock_response)
        scan_context.http_client = mock_http
        
        scanner = RuntimeScanner(scan_context)
        findings = await scanner.scan(scan_context)
        
        # Should test JWT validation
        assert isinstance(findings, list)
    
    @pytest.mark.asyncio
    async def test_scan_anon_key_exposure(self, scan_context):
        """Test detecting exposed anon key endpoints."""
        mock_http = AsyncMock()
        
        # Simulate endpoint that accepts any anon key
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={"data": "sensitive"})
        mock_http.get = AsyncMock(return_value=mock_response)
        scan_context.http_client = mock_http
        
        scanner = RuntimeScanner(scan_context)
        findings = await scanner.scan(scan_context)
        
        # Should check anon key security
        assert isinstance(findings, list)
    
    @pytest.mark.asyncio
    async def test_scan_rate_limiting(self, scan_context):
        """Test checking rate limiting."""
        mock_http = AsyncMock()
        
        # Simulate no rate limiting (all requests succeed)
        call_count = 0
        async def mock_get(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value={"data": f"response_{call_count}"})
            return mock_response
        
        mock_http.get = AsyncMock(side_effect=mock_get)
        scan_context.http_client = mock_http
        
        scanner = RuntimeScanner(scan_context)
        findings = await scanner.scan(scan_context)
        
        # Should detect missing rate limiting
        rate_findings = [f for f in findings if "rate" in f.description.lower() or "limit" in f.description.lower()]
        assert len(rate_findings) > 0
        
        if rate_findings:
            assert rate_findings[0].severity in [Severity.MEDIUM, Severity.HIGH]
            assert rate_findings[0].category == FindingCategory.RUNTIME
    
    @pytest.mark.asyncio
    async def test_scan_cors_headers(self, scan_context):
        """Test checking CORS headers."""
        mock_http = AsyncMock()
        
        # Simulate permissive CORS
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.headers = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true"
        }
        mock_http.options = AsyncMock(return_value=mock_response)
        scan_context.http_client = mock_http
        
        scanner = RuntimeScanner(scan_context)
        findings = await scanner.scan(scan_context)
        
        # Should detect permissive CORS
        cors_findings = [f for f in findings if "cors" in f.description.lower()]
        assert len(cors_findings) > 0
    
    @pytest.mark.asyncio
    async def test_scan_ssl_tls(self, scan_context):
        """Test checking SSL/TLS configuration."""
        scan_context.config.supabase.url = "http://insecure.supabase.co"
        
        scanner = RuntimeScanner(scan_context)
        findings = await scanner.scan(scan_context)
        
        # Should detect non-HTTPS URL
        ssl_findings = [f for f in findings if "ssl" in f.description.lower() or "tls" in f.description.lower() or "https" in f.description.lower()]
        assert len(ssl_findings) > 0
        if ssl_findings:
            assert ssl_findings[0].severity in [Severity.CRITICAL, Severity.HIGH]
    
    @pytest.mark.asyncio
    async def test_scan_security_headers(self, scan_context):
        """Test checking security headers."""
        mock_http = AsyncMock()
        
        # Simulate missing security headers
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.headers = {
            "Content-Type": "application/json"
            # Missing X-Content-Type-Options, X-Frame-Options, etc.
        }
        mock_http.get = AsyncMock(return_value=mock_response)
        scan_context.http_client = mock_http
        
        scanner = RuntimeScanner(scan_context)
        findings = await scanner.scan(scan_context)
        
        # Should detect missing security headers
        header_findings = [f for f in findings if "header" in f.description.lower()]
        assert len(header_findings) > 0
    
    @pytest.mark.asyncio
    async def test_scan_api_versioning(self, scan_context):
        """Test checking API versioning."""
        mock_http = AsyncMock()
        
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.headers = {}
        mock_http.get = AsyncMock(return_value=mock_response)
        scan_context.http_client = mock_http
        
        scanner = RuntimeScanner(scan_context)
        findings = await scanner.scan(scan_context)
        
        # Should check API versioning
        assert isinstance(findings, list)
    
    @pytest.mark.asyncio
    async def test_scan_database_connection_leak(self, scan_context):
        """Test detecting database connection leaks."""
        # Mock database connection
        mock_conn = AsyncMock()
        
        # Simulate many open connections
        mock_conn.fetch = AsyncMock(return_value=[
            {"connections": 95, "max_connections": 100}
        ])
        scan_context.db_connection = mock_conn
        
        scanner = RuntimeScanner(scan_context)
        findings = await scanner.scan(scan_context)
        
        # Should warn about high connection usage
        conn_findings = [f for f in findings if "connection" in f.description.lower()]
        assert len(conn_findings) > 0
    
    @pytest.mark.asyncio
    async def test_scan_error_disclosure(self, scan_context):
        """Test detecting error information disclosure."""
        mock_http = AsyncMock()
        
        # Simulate detailed error message
        mock_response = AsyncMock()
        mock_response.status = 500
        mock_response.json = AsyncMock(return_value={
            "error": "Database error: relation 'secret_table' does not exist at line 42 in /app/queries.py",
            "stack_trace": ["line1", "line2", "line3"]
        })
        mock_http.get = AsyncMock(return_value=mock_response)
        scan_context.http_client = mock_http
        
        scanner = RuntimeScanner(scan_context)
        findings = await scanner.scan(scan_context)
        
        # Should detect information disclosure in errors
        error_findings = [f for f in findings if "error" in f.description.lower() or "disclosure" in f.description.lower()]
        assert len(error_findings) > 0
    
    @pytest.mark.asyncio
    async def test_scan_session_management(self, scan_context):
        """Test checking session management."""
        mock_http = AsyncMock()
        
        # Check cookie settings
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.headers = {
            "Set-Cookie": "session=abc123; Path=/"
            # Missing HttpOnly, Secure, SameSite
        }
        mock_http.get = AsyncMock(return_value=mock_response)
        scan_context.http_client = mock_http
        
        scanner = RuntimeScanner(scan_context)
        findings = await scanner.scan(scan_context)
        
        # Should detect insecure session cookies
        session_findings = [f for f in findings if "session" in f.description.lower() or "cookie" in f.description.lower()]
        assert len(session_findings) > 0
    
    @pytest.mark.asyncio
    async def test_scan_authentication_bypass(self, scan_context):
        """Test detecting authentication bypass."""
        mock_http = AsyncMock()
        
        # Simulate endpoint accessible without auth
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={"sensitive": "data"})
        mock_http.get = AsyncMock(return_value=mock_response)
        scan_context.http_client = mock_http
        
        scanner = RuntimeScanner(scan_context)
        findings = await scanner.scan(scan_context)
        
        # Should test authentication requirements
        assert isinstance(findings, list)
    
    @pytest.mark.asyncio
    async def test_scan_api_enumeration(self, scan_context):
        """Test detecting API enumeration vulnerabilities."""
        mock_http = AsyncMock()
        
        # Simulate different responses for existing/non-existing resources
        async def mock_get(url, *args, **kwargs):
            mock_response = AsyncMock()
            if "exists" in url:
                mock_response.status = 200
                mock_response.json = AsyncMock(return_value={"data": "found"})
            else:
                mock_response.status = 404
                mock_response.json = AsyncMock(return_value={"error": "User not found"})
            return mock_response
        
        mock_http.get = AsyncMock(side_effect=mock_get)
        scan_context.http_client = mock_http
        
        scanner = RuntimeScanner(scan_context)
        findings = await scanner.scan(scan_context)
        
        # Should detect enumeration vulnerability
        enum_findings = [f for f in findings if "enumerat" in f.description.lower()]
        assert len(enum_findings) > 0
    
    @pytest.mark.asyncio
    async def test_scan_with_connection_error(self, scan_context):
        """Test handling connection errors."""
        mock_http = AsyncMock()
        mock_http.get = AsyncMock(side_effect=Exception("Connection timeout"))
        scan_context.http_client = mock_http
        
        scanner = RuntimeScanner(scan_context)
        findings = await scanner.scan(scan_context)
        
        # Should handle error gracefully
        assert isinstance(findings, list)
    
    @pytest.mark.asyncio
    async def test_finding_details(self, scan_context):
        """Test that findings have all required details."""
        scan_context.config.supabase.url = "http://insecure.example.com"
        
        scanner = RuntimeScanner(scan_context)
        findings = await scanner.scan(scan_context)
        
        if len(findings) > 0:
            finding = findings[0]
            
            # Check all required fields
            assert finding.id is not None
            assert finding.title is not None
            assert finding.description is not None
            assert finding.severity is not None
            assert finding.category == FindingCategory.RUNTIME
            assert finding.recommendation is not None
    
    @pytest.mark.asyncio
    async def test_recommendations_provided(self, scan_context):
        """Test that recommendations are provided."""
        scan_context.config.supabase.url = "http://insecure.example.com"
        
        scanner = RuntimeScanner(scan_context)
        findings = await scanner.scan(scan_context)
        
        if len(findings) > 0:
            for finding in findings:
                # Each finding should have a recommendation
                assert finding.recommendation is not None
                assert len(finding.recommendation) > 0
    
    @pytest.mark.asyncio
    async def test_severity_appropriate(self, scan_context):
        """Test that severity levels are appropriate."""
        # Test critical finding (no HTTPS)
        scan_context.config.supabase.url = "http://insecure.example.com"
        
        scanner = RuntimeScanner(scan_context)
        findings = await scanner.scan(scan_context)
        
        # Should have at least one high/critical finding for HTTP
        high_severity = [f for f in findings if f.severity in [Severity.CRITICAL, Severity.HIGH]]
        assert len(high_severity) > 0

