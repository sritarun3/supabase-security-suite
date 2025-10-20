# Supabase Security Suite - Architecture

## Overview

The Supabase Security Suite is a comprehensive security scanning tool designed specifically for self-hosted Supabase projects. It provides deep analysis of RLS policies, secrets management, Docker configurations, GraphQL endpoints, and runtime behavior.

## Package Structure

```
supabase-security-suite/
├── src/
│   └── supabase_security_suite/
│       ├── __init__.py           # Package exports and version
│       ├── __main__.py           # Module entry point
│       ├── cli/                  # Typer-based CLI
│       │   ├── __init__.py
│       │   ├── main.py           # Main Typer app
│       │   ├── scan.py           # `suite scan` command
│       │   ├── rls_simulate.py   # `suite rls simulate` command
│       │   └── ci.py             # `suite ci` command
│       ├── core/                 # Core utilities and base classes
│       │   ├── __init__.py
│       │   ├── config.py         # Configuration management
│       │   ├── scanner.py        # BaseScanner abstract class
│       │   └── utils.py          # Shared utilities
│       ├── scanners/             # Security scanners
│       │   ├── __init__.py
│       │   ├── semgrep.py        # Static analysis (Semgrep)
│       │   ├── rls_policy.py     # RLS policy analysis
│       │   ├── secrets.py        # Secrets detection
│       │   ├── docker.py         # Docker/environment audit
│       │   ├── graphql.py        # GraphQL security checks
│       │   ├── sql_injection.py  # SQL injection detection
│       │   └── runtime.py        # Runtime behavior analysis
│       ├── integrations/         # External integrations
│       │   ├── __init__.py
│       │   ├── slack.py          # Slack notifications
│       │   ├── jira.py           # Jira ticket creation
│       │   └── github.py         # GitHub integration
│       ├── reporting/            # Report generation
│       │   ├── __init__.py
│       │   ├── models.py         # Pydantic models (Finding, ScanResult)
│       │   ├── exporters.py      # Export to JSON, PDF, Markdown
│       │   ├── compliance.py     # Compliance mapping (HIPAA, ISO, SOC2)
│       │   └── sarif.py          # SARIF output for GitHub Code Scanning
│       ├── simulator/            # RLS simulator
│       │   ├── __init__.py
│       │   ├── rls_simulator.py  # Main simulator logic
│       │   ├── jwt_generator.py  # JWT generation for roles
│       │   └── postgrest_client.py # HTTP client for PostgREST
│       └── dashboard/            # Web dashboard
│           ├── __init__.py
│           ├── server.py         # Flask application
│           ├── templates/        # Jinja2 templates
│           └── static/           # CSS, JS, images
├── tests/                        # Test suite
│   ├── unit/
│   ├── integration/
│   └── fixtures/
├── .github/
│   └── workflows/
│       └── security_scan.yml     # GitHub Actions workflow
├── pyproject.toml                # Package metadata and dependencies
├── setup.py                      # Legacy setup script
├── README.md                     # User documentation
└── ARCHITECTURE.md               # This file

```

## Design Principles

### 1. **Modularity**
Each scanner is an independent module implementing the `BaseScanner` interface. Scanners can be run individually or as part of a full scan.

### 2. **Async-First**
All I/O-bound operations (database queries, HTTP requests, file operations) use `asyncio` for better performance when scanning large projects.

### 3. **Type Safety**
Pydantic models are used throughout for configuration, scan results, and findings. This ensures data integrity and provides excellent IDE support.

### 4. **Extensibility**
New scanners can be added by:
1. Implementing `BaseScanner`
2. Registering the scanner in `scanners/__init__.py`
3. Adding configuration options to `core/config.py`

### 5. **Compliance-First**
All findings are mapped to compliance frameworks (HIPAA, ISO 27001, SOC 2) out of the box, making it easy to generate audit reports.

## Core Components

### Scanner Base Class

```python
class BaseScanner(ABC):
    """Abstract base class for all security scanners."""
    
    @abstractmethod
    async def scan(self, context: ScanContext) -> List[Finding]:
        """Run the scanner and return findings."""
        pass
```

### Scan Context

The `ScanContext` object is passed to all scanners and contains:
- Project path
- Database connection info
- Supabase API URL and keys
- Scanner-specific configuration

### Findings Model

Each scanner returns a list of `Finding` objects:

```python
class Finding(BaseModel):
    id: str
    title: str
    description: str
    severity: Severity  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str       # rls, secrets, docker, graphql, etc.
    source: str         # Scanner name
    location: Optional[Location]
    recommendation: str
    compliance: Dict[str, List[str]]  # Framework -> control IDs
    metadata: Dict[str, Any]
```

## Scanner Details

### 1. RLS Policy Scanner (`rls_policy.py`)

**Purpose:** Analyze PostgreSQL Row Level Security policies for common misconfigurations.

**Checks:**
- Tables without RLS enabled
- Asymmetric USING/WITH CHECK clauses
- Missing indexes on policy filter columns
- Overly permissive policies (e.g., `true` predicates)

**Technology:** Direct `asyncpg` queries to `pg_policies`, `pg_tables`, and `pg_indexes`.

### 2. Secrets Scanner (`secrets.py`)

**Purpose:** Detect leaked API keys, tokens, and credentials.

**Checks:**
- `.env` files committed to git
- Hardcoded `service_role` keys in code
- JWT secrets in configuration files
- High-entropy strings (potential keys)
- Git history scanning for secrets

**Technology:** Regex patterns + entropy analysis + git log parsing.

### 3. Docker Scanner (`docker.py`)

**Purpose:** Audit Docker Compose and Dockerfile configurations.

**Checks:**
- Exposed ports (5432, 8000, 8080) without network restrictions
- Default/weak passwords in environment variables
- Privileged containers
- Missing healthchecks
- Non-root user enforcement

**Technology:** YAML parsing for `docker-compose.yml`, Dockerfile AST analysis.

### 4. GraphQL Scanner (`graphql.py`)

**Purpose:** Test GraphQL endpoint security posture.

**Checks:**
- Introspection enabled for anonymous users
- Schema differences between `anon` and `authenticated` roles
- Mutations accessible to anonymous users
- Depth/complexity limits

**Technology:** HTTP requests to GraphQL endpoint with different auth tokens.

### 5. RLS Simulator (`simulator/`)

**Purpose:** Dynamically test RLS policies by generating JWTs and performing CRUD operations via PostgREST.

**Features:**
- JWT generation with custom claims (role, user_id, email)
- CRUD operations for each table as `anon` and `authenticated`
- Coverage matrix: Table × Operation × Role → Success/Failure
- Detailed error messages for policy violations

**Technology:** `pyjwt` for token generation, `httpx` for PostgREST requests.

## CLI Commands

### `suite scan`

Run security scanners on the project.

```bash
suite scan [TARGET] [OPTIONS]

Options:
  --config PATH          Path to config file (default: config.json)
  --scanners TEXT        Comma-separated list of scanners to run (default: all)
  --output-format TEXT   Output format: json, markdown, pdf, sarif (default: json)
  --output-file PATH     Save results to file
  --verbose              Enable verbose logging
```

### `suite rls simulate`

Test RLS policies by simulating real user operations.

```bash
suite rls simulate [OPTIONS]

Options:
  --config PATH          Path to config file
  --table TEXT           Specific table to test (default: all)
  --operations TEXT      Operations to test: select,insert,update,delete (default: all)
  --roles TEXT           Roles to test: anon,authenticated (default: both)
  --output-file PATH     Save results to file
```

### `suite ci`

Run in CI mode (non-interactive, machine-readable output).

```bash
suite ci [OPTIONS]

Options:
  --config PATH          Path to config file
  --fail-on TEXT         Fail if findings with severity: critical,high,medium,low
  --sarif                Output SARIF format for GitHub Code Scanning
  --exit-code            Exit with non-zero code if findings found
```

### `suite dashboard`

Launch the web dashboard.

```bash
suite dashboard [OPTIONS]

Options:
  --port INTEGER         Port to run on (default: 8080)
  --host TEXT            Host to bind to (default: 0.0.0.0)
  --reports-dir PATH     Directory containing scan reports
```

## Configuration

Configuration is managed via `config.json` (or environment variables):

```json
{
  "database": {
    "host": "localhost",
    "port": 5432,
    "database": "postgres",
    "user": "postgres",
    "password": "postgres"
  },
  "supabase": {
    "url": "http://localhost:8000",
    "anon_key": "...",
    "service_role_key": "...",
    "jwt_secret": "..."
  },
  "scanners": {
    "rls": {
      "enabled": true,
      "check_indexes": true
    },
    "secrets": {
      "enabled": true,
      "scan_git_history": true,
      "entropy_threshold": 4.5
    },
    "docker": {
      "enabled": true
    },
    "graphql": {
      "enabled": true
    }
  },
  "ai": {
    "provider": "openai",
    "api_key": "...",
    "model": "gpt-4"
  },
  "integrations": {
    "slack": {
      "enabled": false,
      "webhook_url": "..."
    },
    "jira": {
      "enabled": false,
      "url": "...",
      "username": "...",
      "api_token": "...",
      "project_key": "..."
    }
  }
}
```

## GitHub Actions Integration

Add to `.github/workflows/security-scan.yml`:

```yaml
name: Supabase Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 0 * * *'  # Daily at midnight

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install Supabase Security Suite
        run: pip install supabase-security-suite
      
      - name: Run Security Scan
        run: suite ci --sarif --output-file security.sarif
        env:
          DATABASE_URL: ${{ secrets.DATABASE_URL }}
          SUPABASE_URL: ${{ secrets.SUPABASE_URL }}
          SUPABASE_SERVICE_ROLE_KEY: ${{ secrets.SUPABASE_SERVICE_ROLE_KEY }}
      
      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: security.sarif
```

## Development

### Local Development Setup

```bash
# Clone the repository
git clone https://github.com/your-org/supabase-security-suite.git
cd supabase-security-suite

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in editable mode with dev dependencies
pip install -e ".[dev,all]"

# Run tests
pytest

# Run linters
black .
ruff check .
mypy src/
```

### Adding a New Scanner

1. Create `src/supabase_security_suite/scanners/my_scanner.py`:

```python
from supabase_security_suite.core.scanner import BaseScanner, ScanContext
from supabase_security_suite.reporting.models import Finding, Severity

class MyScanner(BaseScanner):
    name = "my_scanner"
    
    async def scan(self, context: ScanContext) -> List[Finding]:
        findings = []
        # Your scanning logic here
        return findings
```

2. Register in `src/supabase_security_suite/scanners/__init__.py`:

```python
from supabase_security_suite.scanners.my_scanner import MyScanner

ALL_SCANNERS = [
    # ... existing scanners
    MyScanner,
]
```

3. Add tests in `tests/unit/test_my_scanner.py`

4. Update documentation

## Security Considerations

- **JWT Secrets:** Never log or expose JWT secrets. The simulator generates tokens but doesn't store them.
- **Database Credentials:** Use environment variables or secret managers in production.
- **Service Role Key:** The scanner requires the service role key for comprehensive checks. Treat it as a root password.
- **Git History Scanning:** Can be slow on large repositories. Use `--skip-git-history` for faster scans.

## Performance

- **Async I/O:** All database and HTTP operations are async for parallelism.
- **Connection Pooling:** `asyncpg` connection pools reduce overhead.
- **Incremental Scanning:** Future feature to scan only changed files.

## Roadmap

- [ ] VS Code extension for inline security warnings
- [ ] Real-time monitoring mode
- [ ] AI-powered remediation suggestions
- [ ] Comparison of scans over time (security trends)
- [ ] Support for Supabase Edge Functions scanning
- [ ] Integration with Terraform/IaC tools

## License

MIT License - see LICENSE file for details.
