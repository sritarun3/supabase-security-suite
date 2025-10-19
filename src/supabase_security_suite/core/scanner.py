"""
Base scanner class and scan context for all security scanners.
"""

import logging
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import asyncpg

from supabase_security_suite.core.config import Config
from supabase_security_suite.reporting.models import Finding


@dataclass
class ScanContext:
    """
    Context passed to all scanners containing configuration and shared resources.
    """

    config: Config
    scan_id: str = field(default_factory=lambda: f"scan_{uuid.uuid4().hex[:12]}")
    target_path: Path = field(default_factory=Path.cwd)
    db_pool: Optional[asyncpg.Pool] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    exclude_patterns: List[str] = field(default_factory=list)
    verbose: bool = False
    dry_run: bool = False

    async def get_db_connection(self) -> asyncpg.Connection:
        """Get a database connection from the pool."""
        if self.db_pool is None:
            raise RuntimeError(
                "Database pool not initialized. Call initialize_db_pool() first."
            )
        return await self.db_pool.acquire()

    async def initialize_db_pool(self) -> None:
        """Initialize the database connection pool."""
        if self.db_pool is not None:
            return  # Already initialized

        self.db_pool = await asyncpg.create_pool(
            host=self.config.database.host,
            port=self.config.database.port,
            database=self.config.database.database,
            user=self.config.database.user,
            password=self.config.database.password.get_secret_value(),
            min_size=1,
            max_size=10,
        )

    async def close_db_pool(self) -> None:
        """Close the database connection pool."""
        if self.db_pool:
            await self.db_pool.close()
            self.db_pool = None


class BaseScanner(ABC):
    """
    Abstract base class for all security scanners.

    All scanners must implement the scan() method which returns a list of findings.
    Scanners can be run independently or as part of a full scan.
    """

    # Scanner metadata (to be overridden by subclasses)
    name: str = "base_scanner"
    description: str = "Base scanner class"
    category: str = "general"

    def __init__(self, context: ScanContext):
        """
        Initialize the scanner with a scan context.

        Args:
            context: ScanContext containing configuration and shared resources
        """
        self.context = context
        self.config = context.config
        self.logger = logging.getLogger(f"supabase_security.{self.name}")

    @abstractmethod
    async def scan(self) -> List[Finding]:
        """
        Run the scanner and return a list of findings.

        Returns:
            List of Finding objects discovered by this scanner

        Raises:
            Exception: If the scan fails
        """
        pass

    async def is_enabled(self) -> bool:
        """
        Check if this scanner is enabled in the configuration.

        Returns:
            True if the scanner should run, False otherwise
        """
        # Default implementation checks the scanners config
        scanner_config = getattr(self.config.scanners, self.name, None)
        if scanner_config:
            return getattr(scanner_config, "enabled", True)
        return True

    async def pre_scan(self) -> None:
        """
        Hook called before scan() is run.
        Subclasses can override this for initialization tasks.
        """
        pass

    async def post_scan(self, findings: List[Finding]) -> List[Finding]:
        """
        Hook called after scan() is run.
        Subclasses can override this for cleanup or post-processing.

        Args:
            findings: The findings returned by scan()

        Returns:
            Modified findings (or the same list)
        """
        return findings

    def create_finding(
        self,
        id_suffix: str,
        title: str,
        description: str,
        severity: str,
        category: str,
        location: Optional[Dict[str, Any]] = None,
        recommendation: str = "",
        compliance: Optional[Dict[str, List[str]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Finding:
        """
        Helper method to create a Finding object.

        Args:
            id_suffix: Unique suffix for the finding ID (will be prefixed with scanner name)
            title: Short title describing the issue
            description: Detailed description
            severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)
            category: Category of the finding
            location: Location information (file, line, table, etc.)
            recommendation: How to fix the issue
            compliance: Compliance frameworks and control IDs
            metadata: Additional scanner-specific metadata

        Returns:
            Finding object
        """
        from supabase_security_suite.reporting.models import (
            FindingCategory,
            Location,
            Severity,
        )

        finding_id = f"{self.name}_{id_suffix}"

        return Finding(
            id=finding_id,
            title=title,
            description=description,
            severity=Severity(severity),
            category=FindingCategory(category),
            source=self.name,
            location=Location(**location) if location else None,
            recommendation=recommendation,
            compliance=compliance or {},
            metadata=metadata or {},
        )

    def log(self, message: str, level: str = "INFO") -> None:
        """
        Log a message (will be improved with proper logging later).

        Args:
            message: Message to log
            level: Log level (DEBUG, INFO, WARNING, ERROR)
        """
        if self.config.verbose or level in ("WARNING", "ERROR"):
            print(f"[{level}] [{self.name}] {message}")


class CompositeScanner:
    """
    Runs multiple scanners and aggregates their results.
    """

    def __init__(self, context: ScanContext, scanners: List[BaseScanner]):
        """
        Initialize the composite scanner.

        Args:
            context: ScanContext for all scanners
            scanners: List of scanner instances to run
        """
        self.context = context
        self.scanners = scanners

    async def scan_all(self) -> List[Finding]:
        """
        Run all scanners and aggregate their findings.

        Returns:
            Combined list of findings from all scanners
        """
        all_findings: List[Finding] = []

        for scanner in self.scanners:
            # Check if scanner is enabled
            if not await scanner.is_enabled():
                scanner.log(f"Scanner {scanner.name} is disabled, skipping")
                continue

            scanner.log(f"Running scanner: {scanner.name}")

            try:
                # Run pre-scan hook
                await scanner.pre_scan()

                # Run the actual scan
                findings = await scanner.scan(self.context)

                # Run post-scan hook
                findings = await scanner.post_scan(findings)

                scanner.log(f"Found {len(findings)} issues", level="INFO")
                all_findings.extend(findings)

            except Exception as e:
                scanner.log(f"Scanner failed: {str(e)}", level="ERROR")
                # Optionally, we could continue with other scanners or fail fast
                # For now, we'll log and continue
                continue

        return all_findings


# Export main classes
__all__ = [
    "ScanContext",
    "BaseScanner",
    "CompositeScanner",
]
