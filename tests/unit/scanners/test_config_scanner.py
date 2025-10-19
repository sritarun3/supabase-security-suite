"""
Tests for ConfigurationScanner.
"""

import pytest
from pathlib import Path
from supabase_security_suite.core.scanner import ScanContext
from supabase_security_suite.core.config import Config
from supabase_security_suite.scanners.config_scanner import ConfigurationScanner
from supabase_security_suite.reporting.models import Severity, FindingCategory


@pytest.fixture
def scan_context(tmp_path):
    """Create a test scan context."""
    config = Config()
    config.target = tmp_path
    return ScanContext(config=config, target_path=tmp_path)


@pytest.mark.asyncio
async def test_scanner_initialization(scan_context):
    """Test scanner initialization."""
    scanner = ConfigurationScanner(scan_context)
    assert scanner.name == "config_scanner"
    assert scanner.category == "config"


@pytest.mark.asyncio
async def test_detect_http_url(tmp_path, scan_context):
    """Test detection of HTTP URLs in config."""
    env_file = tmp_path / ".env"
    env_file.write_text("""
API_URL=http://api.example.com
DATABASE_URL=postgres://localhost:5432
""")
    
    scanner = ConfigurationScanner(scan_context)
    findings = await scanner.scan()
    
    http_findings = [f for f in findings if "HTTP" in f.title]
    assert len(http_findings) > 0
    assert http_findings[0].severity == Severity.MEDIUM
    assert http_findings[0].category == FindingCategory.CONFIGURATION


@pytest.mark.asyncio
async def test_ignore_https_url(tmp_path, scan_context):
    """Test that HTTPS URLs are not flagged."""
    env_file = tmp_path / ".env"
    env_file.write_text("""
API_URL=https://api.example.com
SECURE_ENDPOINT=https://secure.example.com
""")
    
    scanner = ConfigurationScanner(scan_context)
    findings = await scanner.scan()
    
    # Should not flag HTTPS
    http_findings = [f for f in findings if "HTTP" in f.title]
    assert len(http_findings) == 0


@pytest.mark.asyncio
async def test_ignore_http_in_comments(tmp_path, scan_context):
    """Test that HTTP URLs in comments are ignored."""
    env_file = tmp_path / ".env"
    env_file.write_text("""
# Example: http://localhost:3000
# Documentation: http://docs.example.com
SECURE_API=https://api.example.com
""")
    
    scanner = ConfigurationScanner(scan_context)
    findings = await scanner.scan()
    
    # Should not flag HTTP in comments
    http_findings = [f for f in findings if "HTTP" in f.title]
    assert len(http_findings) == 0


@pytest.mark.asyncio
async def test_detect_weak_jwt_secret(tmp_path, scan_context):
    """Test detection of weak JWT secrets."""
    env_file = tmp_path / ".env"
    env_file.write_text("""
JWT_SECRET=short123
API_KEY=very-long-api-key-that-is-secure-enough-123456
""")
    
    scanner = ConfigurationScanner(scan_context)
    findings = await scanner.scan()
    
    jwt_findings = [f for f in findings if "JWT" in f.title]
    assert len(jwt_findings) > 0
    assert jwt_findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_detect_debug_mode(tmp_path, scan_context):
    """Test detection of debug mode enabled."""
    config_file = tmp_path / "config.toml"
    config_file.write_text("""
[app]
debug = true
environment = "production"
""")
    
    scanner = ConfigurationScanner(scan_context)
    findings = await scanner.scan()
    
    debug_findings = [f for f in findings if "debug" in f.title.lower()]
    assert len(debug_findings) > 0
    assert debug_findings[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_detect_permissive_cors(tmp_path, scan_context):
    """Test detection of permissive CORS settings."""
    env_file = tmp_path / ".env"
    env_file.write_text("""
CORS_ORIGINS="*"
ALLOWED_HOSTS=example.com
""")
    
    scanner = ConfigurationScanner(scan_context)
    findings = await scanner.scan()
    
    cors_findings = [f for f in findings if "CORS" in f.title]
    assert len(cors_findings) > 0
    assert cors_findings[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_exclude_example_files(tmp_path, scan_context):
    """Test that example files are excluded."""
    # Create example directory
    example_dir = tmp_path / "example"
    example_dir.mkdir()
    
    example_file = example_dir / ".env"
    example_file.write_text("""
JWT_SECRET=weak
API_URL=http://example.com
""")
    
    scanner = ConfigurationScanner(scan_context)
    findings = await scanner.scan()
    
    # Should not find issues in example directory
    example_findings = [f for f in findings if "example" in str(f.location.file)]
    assert len(example_findings) == 0


@pytest.mark.asyncio
async def test_exclude_demo_files(tmp_path, scan_context):
    """Test that demo files are excluded."""
    demo_dir = tmp_path / "demo"
    demo_dir.mkdir()
    
    demo_file = demo_dir / "config.toml"
    demo_file.write_text("""
[app]
debug = true
jwt_secret = "weak"
""")
    
    scanner = ConfigurationScanner(scan_context)
    findings = await scanner.scan()
    
    # Should not find issues in demo files
    demo_findings = [f for f in findings if "demo" in str(f.location.file)]
    assert len(demo_findings) == 0


@pytest.mark.asyncio
async def test_docker_compose_scanning(tmp_path, scan_context):
    """Test scanning of docker-compose files."""
    compose_file = tmp_path / "docker-compose.yml"
    compose_file.write_text("""
version: '3'
services:
  app:
    image: myapp
    environment:
      - API_URL=http://api.local
      - DEBUG=true
""")
    
    scanner = ConfigurationScanner(scan_context)
    findings = await scanner.scan()
    
    # Should detect HTTP and debug mode
    assert len(findings) >= 1


@pytest.mark.asyncio
async def test_no_false_positives_on_secure_config(tmp_path, scan_context):
    """Test that secure configurations don't produce findings."""
    env_file = tmp_path / ".env.production"
    # Use a 33+ character JWT secret that won't be caught by {1,31} pattern
    env_file.write_text("""
API_URL=https://secure-api.example.com
JWT_SECRET=abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGH
DEBUG=false
CORS_ORIGINS=https://app.example.com
""")
    
    scanner = ConfigurationScanner(scan_context)
    findings = await scanner.scan()
    
    # Should have no findings for secure config (JWT secret is 44 chars, > 32, won't match)
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_empty_directory(tmp_path, scan_context):
    """Test scanning empty directory."""
    scanner = ConfigurationScanner(scan_context)
    findings = await scanner.scan()
    
    # Should not crash on empty directory
    assert findings == []

