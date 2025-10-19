"""
Core module for Supabase Security Suite.
Contains configuration, scanner base classes, and utilities.
"""

from supabase_security_suite.core.config import Config, load_config
from supabase_security_suite.core.scanner import BaseScanner, CompositeScanner, ScanContext
from supabase_security_suite.core.utils import (
    calculate_entropy,
    get_environment_info,
    is_high_entropy_string,
    test_database_connection,
)

__all__ = [
    "Config",
    "load_config",
    "BaseScanner",
    "ScanContext",
    "CompositeScanner",
    "test_database_connection",
    "calculate_entropy",
    "is_high_entropy_string",
    "get_environment_info",
]

