"""
Unit tests for scanners.secrets_scanner module.
"""

import pytest
from pathlib import Path

from supabase_security_suite.scanners.secrets_scanner import SecretsScanner
from supabase_security_suite.core.scanner import ScanContext
from supabase_security_suite.reporting.models import Severity, FindingCategory


class TestSecretsScanner:
    """Tests for SecretsScanner."""
    
    def test_scanner_initialization(self, scan_context):
        """Test secrets scanner initialization."""
        scanner = SecretsScanner(scan_context)
        
        assert scanner.name == "secrets_scanner"
        assert "secrets" in scanner.description.lower()
        assert scanner.category == "secrets"
    
    @pytest.mark.asyncio
    async def test_scan_no_secrets(self, scan_context, empty_directory):
        """Test scanning directory with no secrets."""
        context = ScanContext(
            config=scan_context.config,
            target_path=str(empty_directory),
        )
        
        scanner = SecretsScanner(context)
        findings = await scanner.scan(context)
        
        assert findings == []
    
    @pytest.mark.asyncio
    async def test_scan_detect_api_keys(self, scan_context, tmp_path):
        """Test detecting API keys."""
        test_file = tmp_path / "config.py"
        test_file.write_text("""
API_KEY = "sk-1234567890abcdefghijklmnop"
OPENAI_KEY = "sk-proj-1234567890abcdef"
        """)
        
        context = ScanContext(
            config=scan_context.config,
            target_path=str(tmp_path),
        )
        
        scanner = SecretsScanner(context)
        findings = await scanner.scan(context)
        
        # Should detect at least one API key
        assert len(findings) > 0
        api_key_findings = [f for f in findings if "api" in f.title.lower() or "key" in f.title.lower()]
        assert len(api_key_findings) > 0
        
        # Check finding properties
        finding = api_key_findings[0]
        assert finding.severity in [Severity.HIGH, Severity.CRITICAL]
        assert finding.category == FindingCategory.SECRETS
    
    @pytest.mark.asyncio
    async def test_scan_detect_passwords(self, scan_context, tmp_path):
        """Test detecting hardcoded passwords."""
        test_file = tmp_path / "app.py"
        test_file.write_text("""
import psycopg2

conn = psycopg2.connect(
    host="localhost",
    database="mydb",
    user="postgres",
    password="SuperSecret123!"
)
        """)
        
        context = ScanContext(
            config=scan_context.config,
            target_path=str(tmp_path),
        )
        
        scanner = SecretsScanner(context)
        findings = await scanner.scan(context)
        
        # Should detect password
        assert len(findings) > 0
        password_findings = [f for f in findings if "password" in f.title.lower()]
        assert len(password_findings) > 0
    
    @pytest.mark.asyncio
    async def test_scan_detect_jwt_tokens(self, scan_context, tmp_path):
        """Test detecting JWT tokens."""
        test_file = tmp_path / "auth.py"
        test_file.write_text("""
JWT_SECRET = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        """)
        
        context = ScanContext(
            config=scan_context.config,
            target_path=str(tmp_path),
        )
        
        scanner = SecretsScanner(context)
        findings = await scanner.scan(context)
        
        # Should detect JWT tokens
        assert len(findings) > 0
        jwt_findings = [f for f in findings if "jwt" in f.title.lower() or "token" in f.title.lower()]
        assert len(jwt_findings) > 0
    
    @pytest.mark.asyncio
    async def test_scan_env_files(self, scan_context, tmp_path):
        """Test scanning .env files."""
        env_file = tmp_path / ".env"
        env_file.write_text("""
DATABASE_URL=postgresql://user:password@localhost/db
API_KEY=1234567890abcdefghij
SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.service_role
        """)
        
        context = ScanContext(
            config=scan_context.config,
            target_path=str(tmp_path),
        )
        
        scanner = SecretsScanner(context)
        findings = await scanner.scan(context)
        
        # Should detect secrets in .env file
        assert len(findings) > 0
        env_findings = [f for f in findings if f.location and ".env" in f.location.file]
        assert len(env_findings) > 0
    
    @pytest.mark.asyncio
    async def test_scan_high_entropy_strings(self, scan_context, tmp_path):
        """Test detecting high-entropy strings."""
        test_file = tmp_path / "secrets.py"
        test_file.write_text("""
# High entropy string (likely a secret)
SECRET = "Xk7mP9qR2wE5tY8uI0oP3aS4dF6gH1jK"

# Low entropy string (not a secret)
NAME = "John Doe"
        """)
        
        context = ScanContext(
            config=scan_context.config,
            target_path=str(tmp_path),
        )
        
        scanner = SecretsScanner(context)
        findings = await scanner.scan(context)
        
        # Should detect high-entropy string
        # but not the low-entropy name
        assert len(findings) > 0
    
    @pytest.mark.asyncio
    async def test_scan_supabase_keys(self, scan_context, tmp_path):
        """Test detecting Supabase-specific keys."""
        test_file = tmp_path / "supabase.py"
        test_file.write_text("""
SUPABASE_URL = "https://myproject.supabase.co"
SUPABASE_ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSJ9"
SUPABASE_SERVICE_ROLE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJvbGUiOiJzZXJ2aWNlX3JvbGUifQ"
        """)
        
        context = ScanContext(
            config=scan_context.config,
            target_path=str(tmp_path),
        )
        
        scanner = SecretsScanner(context)
        findings = await scanner.scan(context)
        
        # Should detect Supabase keys
        assert len(findings) > 0
        supabase_findings = [f for f in findings if "supabase" in f.title.lower()]
        assert len(supabase_findings) > 0
        
        # Service role key should be higher severity
        service_role_findings = [f for f in supabase_findings if "service" in f.title.lower()]
        if service_role_findings:
            assert service_role_findings[0].severity in [Severity.HIGH, Severity.CRITICAL]
    
    @pytest.mark.asyncio
    async def test_scan_multiple_files(self, scan_context, test_files):
        """Test scanning multiple files."""
        context = ScanContext(
            config=scan_context.config,
            target_path=str(test_files["python"].parent),
        )
        
        scanner = SecretsScanner(context)
        findings = await scanner.scan(context)
        
        # Should detect secrets across multiple files
        assert len(findings) > 0
        
        # Check that findings are from different files
        files_with_findings = {f.location.file for f in findings if f.location}
        assert len(files_with_findings) > 1
    
    @pytest.mark.asyncio
    async def test_scan_binary_files_skipped(self, scan_context, tmp_path):
        """Test that binary files are skipped."""
        # Create a binary file
        binary_file = tmp_path / "image.png"
        binary_file.write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")
        
        # Create a text file with secrets
        text_file = tmp_path / "config.py"
        text_file.write_text('API_KEY = "sk-1234567890"')
        
        context = ScanContext(
            config=scan_context.config,
            target_path=str(tmp_path),
        )
        
        scanner = SecretsScanner(context)
        findings = await scanner.scan(context)
        
        # Should only scan text files
        assert len(findings) > 0
        assert all(f.location is None or ".png" not in f.location.file for f in findings)
    
    @pytest.mark.asyncio
    async def test_exclude_patterns(self, scan_context, tmp_path):
        """Test excluding files by pattern."""
        # Create files
        included_file = tmp_path / "app.py"
        included_file.write_text('API_KEY = "sk-1234567890"')
        
        test_dir = tmp_path / "tests"
        test_dir.mkdir()
        excluded_file = test_dir / "test_config.py"
        excluded_file.write_text('API_KEY = "sk-test-key"')
        
        context = ScanContext(
            config=scan_context.config,
            target_path=str(tmp_path),
            exclude_patterns=["*test*"],
        )
        
        scanner = SecretsScanner(context)
        findings = await scanner.scan(context)
        
        # Should not scan excluded files
        assert len(findings) > 0
        assert all(f.location is None or "test" not in f.location.file.lower() for f in findings)
    
    @pytest.mark.asyncio
    async def test_finding_details(self, scan_context, tmp_path):
        """Test that findings have all required details."""
        test_file = tmp_path / "config.py"
        test_file.write_text("""
# Line 2
API_KEY = "sk-1234567890abcdefghij"
# Line 4
        """)
        
        context = ScanContext(
            config=scan_context.config,
            target_path=str(tmp_path),
        )
        
        scanner = SecretsScanner(context)
        findings = await scanner.scan(context)
        
        assert len(findings) > 0
        finding = findings[0]
        
        # Check all required fields
        assert finding.id is not None
        assert finding.title is not None
        assert finding.description is not None
        assert finding.severity is not None
        assert finding.category == FindingCategory.SECRETS
        assert finding.recommendation is not None
        
        # Check location information
        if finding.location:
            assert finding.location.file is not None
            assert finding.location.line is not None
    
    @pytest.mark.asyncio
    async def test_confidence_scores(self, scan_context, tmp_path):
        """Test confidence scores for different types of secrets."""
        test_file = tmp_path / "mixed.py"
        test_file.write_text("""
# High confidence - known pattern
API_KEY = "sk-1234567890abcdefghij"

# Medium confidence - high entropy
RANDOM_STRING = "Xk7mP9qR2wE5tY8uI0oP"

# Low confidence - looks like a secret but isn't
EXAMPLE_KEY = "your_api_key_here"
        """)
        
        context = ScanContext(
            config=scan_context.config,
            target_path=str(tmp_path),
        )
        
        scanner = SecretsScanner(context)
        findings = await scanner.scan(context)
        
        # Different findings should have different confidence levels
        if len(findings) > 1:
            confidences = [f.confidence for f in findings if f.confidence]
            assert len(set(confidences)) > 1  # Not all the same
    
    @pytest.mark.asyncio
    async def test_recommendations_provided(self, scan_context, tmp_path):
        """Test that recommendations are provided for findings."""
        test_file = tmp_path / "app.py"
        test_file.write_text('API_KEY = "sk-1234567890"')
        
        context = ScanContext(
            config=scan_context.config,
            target_path=str(tmp_path),
        )
        
        scanner = SecretsScanner(context)
        findings = await scanner.scan(context)
        
        assert len(findings) > 0
        for finding in findings:
            # Each finding should have a recommendation
            assert finding.recommendation is not None
            assert len(finding.recommendation) > 0

