"""
Shared utility functions for the Supabase Security Suite.
"""

import hashlib
import math
import platform
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import asyncpg


async def test_database_connection(
    host: str, port: int, database: str, user: str, password: str
) -> bool:
    """
    Test if we can connect to the database.

    Args:
        host: Database host
        port: Database port
        database: Database name
        user: Database user
        password: Database password

    Returns:
        True if connection successful, False otherwise
    """
    try:
        conn = await asyncpg.connect(
            host=host,
            port=port,
            database=database,
            user=user,
            password=password,
            timeout=5,
        )
        await conn.close()
        return True
    except Exception:
        return False


def calculate_entropy(data: str) -> float:
    """
    Calculate Shannon entropy of a string.
    Used for detecting high-entropy strings (potential secrets).

    Args:
        data: String to analyze

    Returns:
        Entropy value (higher = more random)
    """
    if not data:
        return 0.0

    entropy = 0.0
    for x in range(256):
        p_x = float(data.count(chr(x))) / len(data)
        if p_x > 0:
            entropy += -p_x * math.log2(p_x)

    return entropy


def is_high_entropy_string(data: str, threshold: float = 4.5) -> bool:
    """
    Check if a string has high entropy (potential secret).

    Args:
        data: String to check
        threshold: Minimum entropy to be considered high

    Returns:
        True if entropy is above threshold
    """
    return calculate_entropy(data) >= threshold


def hash_string(data: str) -> str:
    """
    Generate SHA256 hash of a string.

    Args:
        data: String to hash

    Returns:
        Hex digest of the hash
    """
    return hashlib.sha256(data.encode()).hexdigest()


def get_file_paths(
    directory: Path,
    include_patterns: Optional[List[str]] = None,
    exclude_patterns: Optional[List[str]] = None,
    max_size_mb: int = 10,
) -> List[Path]:
    """
    Get list of file paths matching patterns.

    Args:
        directory: Root directory to search
        include_patterns: Glob patterns to include (e.g., ["*.py", "*.js"])
        exclude_patterns: Glob patterns to exclude (e.g., ["*.pyc", "node_modules/*"])
        max_size_mb: Skip files larger than this size

    Returns:
        List of Path objects
    """
    files: List[Path] = []

    if include_patterns:
        for pattern in include_patterns:
            files.extend(directory.rglob(pattern))
    else:
        files = list(directory.rglob("*"))

    # Filter out directories
    files = [f for f in files if f.is_file()]

    # Apply exclude patterns
    if exclude_patterns:
        excluded_files = set()
        for pattern in exclude_patterns:
            excluded_files.update(directory.rglob(pattern))
        files = [f for f in files if f not in excluded_files]

    # Filter by size
    max_size_bytes = max_size_mb * 1024 * 1024
    files = [f for f in files if f.stat().st_size <= max_size_bytes]

    return files


def get_environment_info() -> Dict[str, str]:
    """
    Get information about the current environment.

    Returns:
        Dictionary with Python version, OS, etc.
    """
    return {
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "os": platform.system(),
        "os_version": platform.release(),
        "architecture": platform.machine(),
    }


def format_bytes(bytes: int) -> str:
    """
    Format bytes as human-readable string.

    Args:
        bytes: Number of bytes

    Returns:
        Formatted string (e.g., "1.5 MB")
    """
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if bytes < 1024.0:
            return f"{bytes:.1f} {unit}"
        bytes /= 1024.0
    return f"{bytes:.1f} PB"


def redact_secret(secret: str, show_chars: int = 4) -> str:
    """
    Redact a secret, showing only first and last few characters.

    Args:
        secret: Secret string to redact
        show_chars: Number of characters to show at start and end

    Returns:
        Redacted string (e.g., "sk-1234...5678")
    """
    if len(secret) <= show_chars * 2:
        return "*" * len(secret)

    return f"{secret[:show_chars]}...{secret[-show_chars:]}"


async def execute_sql_query(
    conn: asyncpg.Connection, query: str, *args: Any
) -> List[asyncpg.Record]:
    """
    Execute a SQL query and return results.

    Args:
        conn: Database connection
        query: SQL query to execute
        *args: Query parameters

    Returns:
        List of records
    """
    return await conn.fetch(query, *args)


async def check_table_exists(
    conn: asyncpg.Connection, schema: str, table: str
) -> bool:
    """
    Check if a table exists in the database.

    Args:
        conn: Database connection
        schema: Schema name
        table: Table name

    Returns:
        True if table exists
    """
    query = """
        SELECT EXISTS (
            SELECT 1
            FROM information_schema.tables
            WHERE table_schema = $1
            AND table_name = $2
        )
    """
    result = await conn.fetchval(query, schema, table)
    return result


def normalize_path(path: Path, base_path: Optional[Path] = None) -> str:
    """
    Normalize a path for consistent reporting.

    Args:
        path: Path to normalize
        base_path: Base path to make relative to (if provided)

    Returns:
        Normalized path string
    """
    if base_path:
        try:
            return str(path.relative_to(base_path))
        except ValueError:
            # Path is not relative to base_path
            pass

    return str(path.absolute())


def is_binary_file(file_path: Path) -> bool:
    """
    Check if a file is binary (non-text).

    Args:
        file_path: Path to file

    Returns:
        True if file appears to be binary
    """
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(1024)
            # Check for null bytes (common in binary files)
            if b"\x00" in chunk:
                return True
            # Check for high proportion of non-text bytes
            text_chars = bytearray(
                {7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7F}
            )
            non_text = sum(1 for byte in chunk if byte not in text_chars)
            return non_text / len(chunk) > 0.3
    except Exception:
        return True  # If we can't read it, treat as binary


def truncate_string(text: str, max_length: int = 100, suffix: str = "...") -> str:
    """
    Truncate a string to a maximum length.

    Args:
        text: String to truncate
        max_length: Maximum length
        suffix: Suffix to add when truncated

    Returns:
        Truncated string
    """
    if len(text) <= max_length:
        return text

    return text[: max_length - len(suffix)] + suffix


# Export main utility functions
__all__ = [
    "test_database_connection",
    "calculate_entropy",
    "is_high_entropy_string",
    "hash_string",
    "get_file_paths",
    "get_environment_info",
    "format_bytes",
    "redact_secret",
    "execute_sql_query",
    "check_table_exists",
    "normalize_path",
    "is_binary_file",
    "truncate_string",
]

