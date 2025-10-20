"""
Supabase Security Suite - A comprehensive security scanning tool for Supabase deployments

This package provides security analysis capabilities specifically designed for Supabase projects,
including static analysis, runtime testing, database security validation, and compliance mapping.
"""

__version__ = "1.0.0"
__author__ = "Supabase Security Suite Team"
__email__ = "security@supabase.com"

from .core.scanner import SupabaseSecurityScanner
from .core.config import SecurityConfig
from .core.finding import SecurityFinding, FindingSeverity

__all__ = [
    "SupabaseSecurityScanner",
    "SecurityConfig", 
    "SecurityFinding",
    "FindingSeverity"
]
