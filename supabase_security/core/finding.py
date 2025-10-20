"""
Security finding data structures and compliance mapping.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import json


class FindingSeverity(Enum):
    """Security finding severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingSource(Enum):
    """Source of the security finding."""
    STATIC = "static"
    SEMGREP = "semgrep"
    RUNTIME = "runtime"
    DATABASE = "database"
    DOCKER = "docker"
    RLS_SIMULATOR = "rls_simulator"
    SECRET_SCAN = "secret_scan"


@dataclass
class ComplianceMapping:
    """Compliance framework mapping for security findings."""
    
    # SOC 2 Trust Services Criteria
    SOC2: List[str] = field(default_factory=list)
    
    # HIPAA Security Rule
    HIPAA: List[str] = field(default_factory=list)
    
    # ISO 27001 Information Security Management
    ISO27001: List[str] = field(default_factory=list)
    
    # NIST Cybersecurity Framework
    NIST: List[str] = field(default_factory=list)
    
    # OWASP Top 10
    OWASP: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, List[str]]:
        """Convert to dictionary format."""
        return {
            "SOC2": self.SOC2,
            "HIPAA": self.HIPAA,
            "ISO27001": self.ISO27001,
            "NIST": self.NIST,
            "OWASP": self.OWASP
        }
    
    def is_empty(self) -> bool:
        """Check if any compliance mappings exist."""
        return not any([self.SOC2, self.HIPAA, self.ISO27001, self.NIST, self.OWASP])


@dataclass
class SecurityFinding:
    """Represents a security finding with all relevant metadata."""
    
    id: str
    title: str
    severity: FindingSeverity
    confidence: str
    description: str
    impact: str
    recommendation: str
    source: FindingSource
    file: Optional[str] = None
    line: Optional[int] = None
    column: Optional[int] = None
    compliance: ComplianceMapping = field(default_factory=ComplianceMapping)
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary format."""
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "description": self.description,
            "impact": self.impact,
            "recommendation": self.recommendation,
            "source": self.source.value,
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "compliance": self.compliance.to_dict(),
            "cwe_id": self.cwe_id,
            "cvss_score": self.cvss_score,
            "tags": self.tags,
            "metadata": self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SecurityFinding":
        """Create finding from dictionary."""
        compliance_data = data.get("compliance", {})
        compliance = ComplianceMapping(
            SOC2=compliance_data.get("SOC2", []),
            HIPAA=compliance_data.get("HIPAA", []),
            ISO27001=compliance_data.get("ISO27001", []),
            NIST=compliance_data.get("NIST", []),
            OWASP=compliance_data.get("OWASP", [])
        )
        
        return cls(
            id=data["id"],
            title=data["title"],
            severity=FindingSeverity(data["severity"]),
            confidence=data["confidence"],
            description=data["description"],
            impact=data["impact"],
            recommendation=data["recommendation"],
            source=FindingSource(data["source"]),
            file=data.get("file"),
            line=data.get("line"),
            column=data.get("column"),
            compliance=compliance,
            cwe_id=data.get("cwe_id"),
            cvss_score=data.get("cvss_score"),
            tags=data.get("tags", []),
            metadata=data.get("metadata", {})
        )
    
    def get_risk_score(self) -> int:
        """Calculate risk score based on severity and confidence."""
        severity_scores = {
            FindingSeverity.CRITICAL: 25,
            FindingSeverity.HIGH: 15,
            FindingSeverity.MEDIUM: 10,
            FindingSeverity.LOW: 5,
            FindingSeverity.INFO: 1
        }
        
        confidence_multipliers = {
            "HIGH": 1.0,
            "MEDIUM": 0.8,
            "LOW": 0.6
        }
        
        base_score = severity_scores.get(self.severity, 1)
        multiplier = confidence_multipliers.get(self.confidence, 0.6)
        
        return int(base_score * multiplier)


# Predefined compliance mappings for common Supabase security issues
COMPLIANCE_MAPPINGS = {
    "secret:service_role": {
        "SOC2": ["CC6.2", "CC6.7"],
        "HIPAA": ["164.312(a)(1)", "164.312(c)(1)"],
        "ISO27001": ["A.9.2.4", "A.14.2.1"],
        "NIST": ["PR.AC-1", "PR.DS-5"],
        "OWASP": ["A07:2021"]
    },
    "secret:weak_jwt": {
        "SOC2": ["CC6.7"],
        "HIPAA": ["164.312(a)(1)"],
        "ISO27001": ["A.9.1.2", "A.14.2.1"],
        "NIST": ["PR.AC-1", "PR.DS-5"],
        "OWASP": ["A07:2021"]
    },
    "config:cors_wildcard": {
        "SOC2": ["CC6.6"],
        "HIPAA": ["164.312(b)"],
        "ISO27001": ["A.13.2.1"],
        "NIST": ["PR.AC-3", "PR.DS-5"],
        "OWASP": ["A05:2021"]
    },
    "runtime:gql_introspection": {
        "SOC2": ["CC7.2"],
        "HIPAA": ["164.308(a)(1)(ii)(D)"],
        "ISO27001": ["A.14.2.8"],
        "NIST": ["PR.DS-5", "PR.IP-1"],
        "OWASP": ["A05:2021"]
    },
    "db:rls_disabled": {
        "SOC2": ["CC6.7"],
        "HIPAA": ["164.312(a)(1)"],
        "ISO27001": ["A.9.1.2", "A.14.2.1"],
        "NIST": ["PR.AC-1", "PR.DS-5"],
        "OWASP": ["A01:2021"]
    },
    "db:security_definer": {
        "SOC2": ["CC6.3", "CC6.6"],
        "HIPAA": ["164.308(a)(4)(ii)(C)"],
        "ISO27001": ["A.14.2.9", "A.9.2.3"],
        "NIST": ["PR.AC-1", "PR.DS-5"],
        "OWASP": ["A01:2021"]
    }
}


def get_compliance_mapping(finding_id: str) -> ComplianceMapping:
    """Get compliance mapping for a finding ID."""
    mapping_data = COMPLIANCE_MAPPINGS.get(finding_id, {})
    return ComplianceMapping(
        SOC2=mapping_data.get("SOC2", []),
        HIPAA=mapping_data.get("HIPAA", []),
        ISO27001=mapping_data.get("ISO27001", []),
        NIST=mapping_data.get("NIST", []),
        OWASP=mapping_data.get("OWASP", [])
    )
