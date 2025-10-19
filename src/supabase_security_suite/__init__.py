"""
Supabase Security Suite - Comprehensive security scanner for self-hosted Supabase projects.

This package provides:
- RLS policy analysis and testing
- Secrets and key hygiene scanning
- Docker and environment audits
- GraphQL security posture checks
- RLS simulator with JWT generation
- Integration with Slack, Jira, and GitHub
- Beautiful web dashboard for viewing results
"""

__version__ = "2.0.0"
__author__ = "Supabase Security Suite Contributors"
__license__ = "MIT"

# Export main classes for convenient imports
from supabase_security_suite.core.scanner import BaseScanner, ScanContext
from supabase_security_suite.reporting.models import Finding, ScanResult, Severity

__all__ = [
    "__version__",
    "BaseScanner",
    "ScanContext",
    "Finding",
    "ScanResult",
    "Severity",
]

