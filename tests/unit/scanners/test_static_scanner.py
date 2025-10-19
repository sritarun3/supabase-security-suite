"""
Tests for StaticAnalysisScanner.
"""

import pytest
from pathlib import Path
from supabase_security_suite.core.scanner import ScanContext
from supabase_security_suite.core.config import Config
from supabase_security_suite.scanners.static_scanner import StaticAnalysisScanner
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
    scanner = StaticAnalysisScanner(scan_context)
    assert scanner.name == "static_scanner"
    assert scanner.category == "static"


@pytest.mark.asyncio
async def test_detect_eval_usage(tmp_path, scan_context):
    """Test detection of eval() usage."""
    # Create test file with eval
    test_file = tmp_path / "dangerous.py"
    test_file.write_text("""
def process_input(user_input):
    result = eval(user_input)  # Dangerous!
    return result
""")
    
    scanner = StaticAnalysisScanner(scan_context)
    findings = await scanner.scan()
    
    # Should detect eval usage
    eval_findings = [f for f in findings if "eval" in f.title.lower()]
    assert len(eval_findings) > 0
    assert eval_findings[0].severity == Severity.HIGH
    assert eval_findings[0].category == FindingCategory.STATIC


@pytest.mark.asyncio
async def test_detect_exec_usage(tmp_path, scan_context):
    """Test detection of exec() usage."""
    test_file = tmp_path / "dangerous.py"
    test_file.write_text("""
def run_code(code_string):
    exec(code_string)
""")
    
    scanner = StaticAnalysisScanner(scan_context)
    findings = await scanner.scan()
    
    exec_findings = [f for f in findings if "exec" in f.title.lower()]
    assert len(exec_findings) > 0
    assert exec_findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_detect_weak_crypto(tmp_path, scan_context):
    """Test detection of weak cryptography."""
    test_file = tmp_path / "crypto.py"
    test_file.write_text("""
import hashlib

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
""")
    
    scanner = StaticAnalysisScanner(scan_context)
    findings = await scanner.scan()
    
    md5_findings = [f for f in findings if "md5" in f.title.lower()]
    assert len(md5_findings) > 0
    assert md5_findings[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_detect_hardcoded_password(tmp_path, scan_context):
    """Test detection of hardcoded passwords."""
    test_file = tmp_path / "config.py"
    test_file.write_text("""
DATABASE_PASSWORD = "super_secret_password_123"
""")
    
    scanner = StaticAnalysisScanner(scan_context)
    findings = await scanner.scan()
    
    pwd_findings = [f for f in findings if "password" in f.title.lower()]
    assert len(pwd_findings) > 0
    assert pwd_findings[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_exclude_test_files(tmp_path, scan_context):
    """Test that test files are excluded."""
    # Create test directory
    test_dir = tmp_path / "tests"
    test_dir.mkdir()
    
    test_file = test_dir / "test_app.py"
    test_file.write_text("""
def test_something():
    eval("1 + 1")  # This is in a test file
""")
    
    scanner = StaticAnalysisScanner(scan_context)
    findings = await scanner.scan()
    
    # Should not find issues in test files
    test_findings = [f for f in findings if "test_app.py" in str(f.location.file)]
    assert len(test_findings) == 0


@pytest.mark.asyncio
async def test_exclude_comments(tmp_path, scan_context):
    """Test that comments are excluded."""
    test_file = tmp_path / "app.py"
    test_file.write_text("""
# Don't use eval() - it's dangerous
def safe_function():
    return 42
""")
    
    scanner = StaticAnalysisScanner(scan_context)
    findings = await scanner.scan()
    
    # Should not flag eval in comment
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_javascript_file_scanning(tmp_path, scan_context):
    """Test scanning of JavaScript files."""
    test_file = tmp_path / "app.js"
    test_file.write_text("""
function dangerous(input) {
    return eval(input);  // Bad practice
}
""")
    
    scanner = StaticAnalysisScanner(scan_context)
    findings = await scanner.scan()
    
    # Should detect eval in JS files
    eval_findings = [f for f in findings if "eval" in f.title.lower()]
    assert len(eval_findings) > 0


@pytest.mark.asyncio
async def test_empty_directory(tmp_path, scan_context):
    """Test scanning empty directory."""
    scanner = StaticAnalysisScanner(scan_context)
    findings = await scanner.scan()
    
    # Should not crash on empty directory
    assert findings == []

