"""
Pytest configuration and shared fixtures for the Supabase Security Suite.
"""

import asyncio
import json
import tempfile
from pathlib import Path
from typing import Dict, Any
from unittest.mock import Mock, AsyncMock

import pytest
from pydantic import SecretStr

from supabase_security_suite.core.config import (
    Config,
    DatabaseConfig,
    SupabaseConfig,
    ScannersConfig,
    AIConfig,
)
from supabase_security_suite.core.scanner import ScanContext
from supabase_security_suite.reporting.models import (
    Severity,
    FindingCategory,
    Finding,
    Location,
    ScanResult,
    ScanMetadata,
    ScanStatistics,
)


# ============================================================================
# Pytest Configuration
# ============================================================================

def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line("markers", "unit: Unit tests")
    config.addinivalue_line("markers", "integration: Integration tests")
    config.addinivalue_line("markers", "slow: Slow running tests")
    config.addinivalue_line("markers", "requires_db: Requires database connection")
    config.addinivalue_line("markers", "requires_network: Requires network access")


@pytest.fixture(scope="session")
def event_loop():
    """Create an event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


# ============================================================================
# Configuration Fixtures
# ============================================================================

@pytest.fixture
def minimal_config() -> Config:
    """Create a minimal valid configuration."""
    return Config(
        database=DatabaseConfig(
            host="localhost",
            port=5432,
            database="postgres",
            user="postgres",
            password=SecretStr("test"),
        ),
        supabase=SupabaseConfig(
            url="http://localhost:54321",
            anon_key=SecretStr("test-anon-key"),
            service_role_key=SecretStr("test-service-role-key"),
        ),
        scanners=ScannersConfig(),
    )


@pytest.fixture
def full_config(tmp_path: Path) -> Config:
    """Create a fully configured Config object."""
    return Config(
        database=DatabaseConfig(
            host="localhost",
            port=5432,
            database="test_db",
            user="test_user",
            password=SecretStr("test_password"),
            ssl_mode="prefer",
        ),
        supabase=SupabaseConfig(
            url="https://test.supabase.co",
            anon_key=SecretStr("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test"),
            service_role_key=SecretStr("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.service"),
            jwt_secret=SecretStr("test-jwt-secret"),
        ),
        ai=AIConfig(
            provider="openai",
            openai_api_key=SecretStr("sk-test-key"),
            enabled=True,
        ),
    )


@pytest.fixture
def config_file(tmp_path: Path, full_config: Config) -> Path:
    """Create a temporary config file."""
    config_path = tmp_path / "config.json"
    config_dict = full_config.model_dump(mode="json")
    
    # Convert SecretStr to plain strings for JSON serialization
    def convert_secrets(obj):
        if isinstance(obj, dict):
            return {k: convert_secrets(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [convert_secrets(item) for item in obj]
        elif hasattr(obj, "get_secret_value"):
            return obj.get_secret_value()
        return obj
    
    config_dict = convert_secrets(config_dict)
    
    with open(config_path, "w") as f:
        json.dump(config_dict, f, indent=2)
    
    return config_path


# ============================================================================
# Scanner Fixtures
# ============================================================================

@pytest.fixture
def scan_context(minimal_config: Config, tmp_path: Path) -> ScanContext:
    """Create a scan context for testing."""
    return ScanContext(
        config=minimal_config,
        target_path=tmp_path,
    )


@pytest.fixture
def mock_db_connection():
    """Mock database connection."""
    conn = AsyncMock()
    conn.execute = AsyncMock(return_value=None)
    conn.fetch = AsyncMock(return_value=[])
    conn.fetchrow = AsyncMock(return_value=None)
    conn.fetchval = AsyncMock(return_value=None)
    conn.close = AsyncMock()
    return conn


# ============================================================================
# Finding Fixtures
# ============================================================================

@pytest.fixture
def sample_finding() -> Finding:
    """Create a sample finding for testing."""
    return Finding(
        id="TEST-001",
        title="Test Security Finding",
        description="This is a test security finding",
        severity=Severity.HIGH,
        category=FindingCategory.RLS,
        source="test_scanner",
        recommendation="Fix this issue immediately",
        location=Location(
            file="test.sql",
            line=10,
            column=5,
        ),
        metadata={
            "confidence": 0.9,
            "impact": "High impact test finding",
            "affected_resource": "test.table",
            "cwe_ids": ["CWE-89"],
            "references": ["https://cwe.mitre.org/data/definitions/89.html"],
        }
    )


@pytest.fixture
def sample_findings(sample_finding: Finding) -> list[Finding]:
    """Create multiple sample findings."""
    findings = [sample_finding]
    
    # Add a CRITICAL finding
    findings.append(
        Finding(
            id="TEST-002",
            title="Critical SQL Injection",
            description="SQL injection vulnerability detected",
            severity=Severity.CRITICAL,
            category=FindingCategory.SQL_INJECTION,
            source="sql_injection_scanner",
            recommendation="Use parameterized queries",
            metadata={
                "confidence": 0.95,
                "impact": "Database compromise possible",
                "affected_resource": "users table",
                "cwe_ids": ["CWE-89"],
            }
        )
    )
    
    # Add a MEDIUM finding
    findings.append(
        Finding(
            id="TEST-003",
            title="Exposed API Key",
            description="API key found in source code",
            severity=Severity.MEDIUM,
            category=FindingCategory.SECRETS,
            source="secrets_scanner",
            recommendation="Move to environment variables",
            location=Location(file="config.py", line=25),
            metadata={
                "confidence": 0.8,
                "impact": "API key exposure",
                "affected_resource": "config.py",
            }
        )
    )
    
    return findings


@pytest.fixture
def scan_result(sample_findings: list[Finding]) -> ScanResult:
    """Create a sample scan result."""
    return ScanResult(
        metadata=ScanMetadata(
            scan_id="scan_test_001",
            target="/test/path",
            duration_seconds=5.0,
            scanners_used=["rls_scanner", "secrets_scanner"],
        ),
        findings=sample_findings,
        statistics=ScanStatistics(
            total_findings=len(sample_findings),
            by_severity={
                Severity.CRITICAL: 1,
                Severity.HIGH: 1,
                Severity.MEDIUM: 1,
            },
            by_category={
                FindingCategory.RLS: 1,
                FindingCategory.SQL_INJECTION: 1,
                FindingCategory.SECRETS: 1,
            },
        ),
        score=45,
    )


# ============================================================================
# File System Fixtures
# ============================================================================

@pytest.fixture
def test_files(tmp_path: Path) -> Dict[str, Path]:
    """Create test files with various security issues."""
    files = {}
    
    # Python file with secrets
    py_file = tmp_path / "app.py"
    py_file.write_text("""
import os

# Exposed secrets
API_KEY = "sk-1234567890abcdef"
DB_PASSWORD = "SuperSecret123!"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"

def connect_db():
    conn = psycopg2.connect(
        host="localhost",
        database="mydb",
        user="postgres",
        password="hardcoded_password"
    )
    return conn
""")
    files["python"] = py_file
    
    # SQL file with RLS issues
    sql_file = tmp_path / "schema.sql"
    sql_file.write_text("""
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email TEXT NOT NULL,
    password TEXT NOT NULL
);

-- No RLS policy!

CREATE TABLE public_data (
    id SERIAL PRIMARY KEY,
    data TEXT
);

ALTER TABLE public_data ENABLE ROW LEVEL SECURITY;
-- Missing policy
""")
    files["sql"] = sql_file
    
    # Docker compose file
    docker_file = tmp_path / "docker-compose.yml"
    docker_file.write_text("""
version: '3.8'
services:
  db:
    image: postgres:latest
    environment:
      POSTGRES_PASSWORD: weak_password
    ports:
      - "5432:5432"
  
  api:
    image: my-api:latest
    ports:
      - "80:8080"
    environment:
      DEBUG: "true"
      SECRET_KEY: "hardcoded-secret"
""")
    files["docker"] = docker_file
    
    # .env file with secrets
    env_file = tmp_path / ".env"
    env_file.write_text("""
DATABASE_URL=postgresql://user:password@localhost/db
API_KEY=1234567890abcdefghij
SUPABASE_URL=https://myproject.supabase.co
SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.service_role
""")
    files["env"] = env_file
    
    return files


@pytest.fixture
def empty_directory(tmp_path: Path) -> Path:
    """Create an empty directory for testing."""
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    return empty_dir


# ============================================================================
# Mock External Services
# ============================================================================

@pytest.fixture
def mock_postgrest_client():
    """Mock PostgREST client."""
    client = Mock()
    client.from_ = Mock(return_value=client)
    client.select = Mock(return_value=client)
    client.insert = Mock(return_value=client)
    client.update = Mock(return_value=client)
    client.delete = Mock(return_value=client)
    client.eq = Mock(return_value=client)
    client.execute = Mock(return_value={"data": [], "status": 200})
    return client


@pytest.fixture
def mock_ai_client():
    """Mock AI service client."""
    client = AsyncMock()
    client.chat = AsyncMock(return_value={
        "choices": [{
            "message": {
                "content": "This is a security issue that should be fixed."
            }
        }]
    })
    return client


# ============================================================================
# Test Data
# ============================================================================

@pytest.fixture
def sample_rls_policies():
    """Sample RLS policies for testing."""
    return [
        {
            "schemaname": "public",
            "tablename": "users",
            "policyname": "users_select_policy",
            "permissive": "PERMISSIVE",
            "roles": ["authenticated"],
            "cmd": "SELECT",
            "qual": "(auth.uid() = user_id)",
            "with_check": None,
        },
        {
            "schemaname": "public",
            "tablename": "posts",
            "policyname": "posts_all_policy",
            "permissive": "PERMISSIVE",
            "roles": ["authenticated"],
            "cmd": "ALL",
            "qual": "(auth.uid() = author_id)",
            "with_check": "(auth.uid() = author_id)",
        },
    ]


@pytest.fixture
def sample_secrets():
    """Sample secrets for testing."""
    return [
        {
            "type": "api_key",
            "value": "sk-1234567890abcdef",
            "file": "config.py",
            "line": 10,
            "entropy": 4.5,
        },
        {
            "type": "password",
            "value": "SuperSecret123!",
            "file": "app.py",
            "line": 25,
            "entropy": 3.8,
        },
        {
            "type": "jwt_secret",
            "value": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
            "file": "auth.py",
            "line": 5,
            "entropy": 4.2,
        },
    ]


# ============================================================================
# Cleanup
# ============================================================================

@pytest.fixture(autouse=True)
def cleanup_temp_files(tmp_path):
    """Automatically cleanup temporary files after each test."""
    yield
    # Cleanup happens automatically with tmp_path

