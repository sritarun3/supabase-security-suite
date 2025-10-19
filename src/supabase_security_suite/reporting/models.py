"""
Pydantic models for security findings and scan results.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Severity levels for security findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingCategory(str, Enum):
    """Categories for security findings."""

    RLS = "rls"
    SECRETS = "secrets"
    DOCKER = "docker"
    GRAPHQL = "graphql"
    SQL_INJECTION = "sql_injection"
    RUNTIME = "runtime"
    STATIC = "static"
    DATABASE = "db"
    CONFIGURATION = "config"
    NETWORK = "network"
    AUTHENTICATION = "authentication"


class Location(BaseModel):
    """Location information for a finding."""

    file: Optional[str] = None
    line: Optional[int] = None
    column: Optional[int] = None
    table: Optional[str] = None
    policy: Optional[str] = None
    function: Optional[str] = None


class Finding(BaseModel):
    """A single security finding."""

    id: str = Field(..., description="Unique identifier for the finding")
    title: str = Field(..., description="Short title describing the issue")
    description: str = Field(..., description="Detailed description of the issue")
    severity: Severity = Field(..., description="Severity level")
    category: FindingCategory = Field(..., description="Category of the finding")
    source: str = Field(..., description="Scanner that found this issue")
    location: Optional[Location] = Field(None, description="Location of the issue")
    recommendation: str = Field(..., description="How to fix the issue")
    ai_recommendation: Optional[str] = Field(
        None, description="AI-generated remediation advice"
    )
    compliance: Dict[str, List[str]] = Field(
        default_factory=dict,
        description="Compliance frameworks and control IDs (e.g., HIPAA, ISO27001)",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict, description="Additional scanner-specific metadata"
    )
    discovered_at: datetime = Field(
        default_factory=datetime.utcnow, description="When the finding was discovered"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "id": "rls_001",
                "title": "Missing RLS on public.users table",
                "description": "The public.users table does not have Row Level Security enabled",
                "severity": "CRITICAL",
                "category": "rls",
                "source": "rls_policy_scanner",
                "location": {"table": "public.users"},
                "recommendation": "Enable RLS: ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;",
                "compliance": {
                    "HIPAA": ["164.312(a)(1)"],
                    "ISO27001": ["A.9.2.4"],
                    "SOC2": ["CC6.1"],
                },
                "metadata": {"has_policies": False, "has_grants": True},
            }
        }


class ScanStatistics(BaseModel):
    """Statistics about the scan results."""

    total_findings: int = Field(0, description="Total number of findings")
    by_severity: Dict[Severity, int] = Field(default_factory=dict)
    by_category: Dict[str, int] = Field(default_factory=dict)
    by_source: Dict[str, int] = Field(default_factory=dict)


class ScanMetadata(BaseModel):
    """Metadata about the scan."""

    scan_id: str = Field(..., description="Unique identifier for this scan")
    timestamp: datetime = Field(
        default_factory=datetime.utcnow, description="When the scan was run"
    )
    duration_seconds: float = Field(..., description="How long the scan took")
    target: str = Field(..., description="What was scanned (path, URL, etc.)")
    scanners_used: List[str] = Field(
        default_factory=list, description="Which scanners were run"
    )
    environment: Dict[str, str] = Field(
        default_factory=dict,
        description="Environment info (Python version, OS, etc.)",
    )


class ScanResult(BaseModel):
    """Complete scan result with all findings and metadata."""

    findings: List[Finding] = Field(
        default_factory=list, description="All security findings"
    )
    metadata: ScanMetadata = Field(..., description="Scan metadata")
    statistics: ScanStatistics = Field(
        default_factory=ScanStatistics, description="Aggregated statistics"
    )
    score: int = Field(100, ge=0, le=100, description="Security score (0-100)")

    def model_post_init(self, __context) -> None:
        """Post-initialization: update statistics if findings are provided."""
        if self.findings:
            self._update_statistics()
            # Only update score if it's still at the default value
            if self.score == 100:
                self._update_score()

    def add_finding(self, finding: Finding) -> None:
        """Add a finding and update statistics."""
        self.findings.append(finding)
        self._update_statistics()
        self._update_score()

    def _update_statistics(self) -> None:
        """Recalculate statistics based on current findings."""
        self.statistics.total_findings = len(self.findings)

        # Count by severity
        self.statistics.by_severity = {}
        for severity in Severity:
            count = sum(1 for f in self.findings if f.severity == severity)
            if count > 0:
                self.statistics.by_severity[severity] = count

        # Count by category
        self.statistics.by_category = {}
        for finding in self.findings:
            category = finding.category.value
            self.statistics.by_category[category] = (
                self.statistics.by_category.get(category, 0) + 1
            )

        # Count by source
        self.statistics.by_source = {}
        for finding in self.findings:
            source = finding.source
            self.statistics.by_source[source] = (
                self.statistics.by_source.get(source, 0) + 1
            )

    def _update_score(self) -> None:
        """Calculate security score based on findings."""
        # Start with 100 and deduct points based on severity
        score = 100

        severity_weights = {
            Severity.CRITICAL: 10,
            Severity.HIGH: 5,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }

        for finding in self.findings:
            score -= severity_weights.get(finding.severity, 0)

        self.score = max(0, score)

    def get_findings_by_severity(self, severity: Severity) -> List[Finding]:
        """Get all findings of a specific severity."""
        return [f for f in self.findings if f.severity == severity]

    def get_findings_by_category(self, category: FindingCategory) -> List[Finding]:
        """Get all findings of a specific category."""
        return [f for f in self.findings if f.category == category]

    def has_critical_findings(self) -> bool:
        """Check if there are any critical findings."""
        return any(f.severity == Severity.CRITICAL for f in self.findings)

    class Config:
        json_schema_extra = {
            "example": {
                "findings": [],
                "metadata": {
                    "scan_id": "scan_2024_01_15_123456",
                    "timestamp": "2024-01-15T12:34:56Z",
                    "duration_seconds": 45.2,
                    "target": "/path/to/project",
                    "scanners_used": ["rls", "secrets", "docker"],
                    "environment": {"python": "3.11", "os": "Linux"},
                },
                "statistics": {
                    "total": 0,
                    "by_severity": {},
                    "by_category": {},
                    "by_source": {},
                },
                "score": 100,
            }
        }

