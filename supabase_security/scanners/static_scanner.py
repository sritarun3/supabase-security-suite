"""
Static analysis scanner for Supabase projects.
"""

import re
import math
from pathlib import Path
from typing import Dict, List, Optional, Any
from collections import Counter

from ..core.finding import SecurityFinding, FindingSeverity, FindingSource, get_compliance_mapping
from ..core.config import SecurityConfig


class StaticScanner:
    """Static analysis scanner for code and configuration files."""
    
    def __init__(self, project_path: Path, config: SecurityConfig):
        self.project_path = project_path
        self.config = config
        
        # File extensions to scan
        self.scan_extensions = set(config.scan_settings.scan_extensions)
        
        # Security patterns
        self.patterns = {
            "cors_wildcard": {
                "pattern": r"(?i)(?:cors|allowed[_-]?origins?)\s*[:=].*(\*|\[.*\*.*\])",
                "severity": FindingSeverity.MEDIUM,
                "description": "CORS wildcard configuration detected",
                "impact": "Wildcard CORS allows requests from any origin",
                "recommendation": "Specify explicit allowed origins instead of wildcards"
            },
            "http_url": {
                "pattern": r"http://[A-Za-z0-9.\-:]+",
                "severity": FindingSeverity.MEDIUM,
                "description": "HTTP URL detected (non-HTTPS)",
                "impact": "HTTP traffic is not encrypted and vulnerable to interception",
                "recommendation": "Use HTTPS URLs for all external connections"
            },
            "weak_password": {
                "pattern": r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]?(?:password|123456|admin|test|changeme)['\"]?",
                "severity": FindingSeverity.HIGH,
                "description": "Weak password detected",
                "impact": "Weak passwords are easily guessable",
                "recommendation": "Use strong, unique passwords"
            },
            "debug_mode": {
                "pattern": r"(?i)(?:debug|dev)\s*[:=]\s*(?:true|1|yes|on)",
                "severity": FindingSeverity.MEDIUM,
                "description": "Debug mode enabled",
                "impact": "Debug mode may expose sensitive information",
                "recommendation": "Disable debug mode in production"
            },
            "console_log": {
                "pattern": r"console\.(log|warn|error|info)\s*\(",
                "severity": FindingSeverity.LOW,
                "description": "Console logging detected",
                "impact": "Console logs may expose sensitive information in production",
                "recommendation": "Remove or conditionally disable console logging"
            },
            "eval_usage": {
                "pattern": r"\beval\s*\(",
                "severity": FindingSeverity.HIGH,
                "description": "eval() function usage detected",
                "impact": "eval() can execute arbitrary code and is a security risk",
                "recommendation": "Avoid using eval() and use safer alternatives"
            },
            "innerHTML": {
                "pattern": r"\.innerHTML\s*=",
                "severity": FindingSeverity.MEDIUM,
                "description": "innerHTML assignment detected",
                "impact": "innerHTML can lead to XSS vulnerabilities",
                "recommendation": "Use textContent or proper sanitization"
            },
            "sql_injection": {
                "pattern": r"(?i)(?:SELECT|INSERT|UPDATE|DELETE)\s+.*\+.*['\"]",
                "severity": FindingSeverity.HIGH,
                "description": "Potential SQL injection vulnerability",
                "impact": "String concatenation in SQL can lead to injection attacks",
                "recommendation": "Use parameterized queries or prepared statements"
            }
        }
    
    def scan_project(self) -> List[SecurityFinding]:
        """Scan the entire project for security issues."""
        findings = []
        
        # Get all files to scan
        files_to_scan = []
        for file_path in self.project_path.rglob("*"):
            if (file_path.is_file() and 
                not self._should_skip_file(file_path) and
                (file_path.suffix.lower() in self.scan_extensions or 
                 file_path.name.startswith('.env'))):
                files_to_scan.append(file_path)
        
        # Scan each file
        for file_path in files_to_scan:
            file_findings = self.scan_file(file_path)
            findings.extend(file_findings)
        
        return findings
    
    def scan_file(self, file_path: Path) -> List[SecurityFinding]:
        """Scan a single file for security issues."""
        findings = []
        
        try:
            # Check file size
            if file_path.stat().st_size > self.config.scan_settings.max_file_size:
                return findings
            
            content = file_path.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            return findings
        
        # Skip binary files
        if self._is_binary_file(content):
            return findings
        
        # Scan for each pattern
        for pattern_name, pattern_info in self.patterns.items():
            matches = re.finditer(pattern_info["pattern"], content, re.MULTILINE)
            
            for match in matches:
                line_number = content[:match.start()].count('\n') + 1
                
                finding = SecurityFinding(
                    id=f"static:{pattern_name}:{file_path}:{match.start()}",
                    title=pattern_info["description"],
                    severity=pattern_info["severity"],
                    confidence="MEDIUM",
                    description=f"Pattern detected in {file_path.name} at line {line_number}",
                    impact=pattern_info["impact"],
                    recommendation=pattern_info["recommendation"],
                    file=str(file_path),
                    line=line_number,
                    source=FindingSource.STATIC,
                    compliance=get_compliance_mapping(f"static:{pattern_name}")
                )
                
                findings.append(finding)
        
        # Additional Supabase-specific checks
        supabase_findings = self._check_supabase_patterns(file_path, content)
        findings.extend(supabase_findings)
        
        return findings
    
    def _check_supabase_patterns(self, file_path: Path, content: str) -> List[SecurityFinding]:
        """Check for Supabase-specific security patterns."""
        findings = []
        
        # Check for direct database access without RLS
        if "createClient" in content and "supabase" in content.lower():
            # Look for direct table access patterns
            direct_access_pattern = r"\.from\s*\(\s*['\"]([^'\"]+)['\"]\s*\)\s*\.(select|insert|update|delete)"
            matches = re.finditer(direct_access_pattern, content, re.IGNORECASE)
            
            for match in matches:
                table_name = match.group(1)
                operation = match.group(2)
                line_number = content[:match.start()].count('\n') + 1
                
                finding = SecurityFinding(
                    id=f"supabase:direct_access:{file_path}:{match.start()}",
                    title=f"Direct database access to {table_name}",
                    severity=FindingSeverity.MEDIUM,
                    confidence="MEDIUM",
                    description=f"Direct {operation} operation on {table_name} without explicit RLS check",
                    impact="Direct database access may bypass RLS policies",
                    recommendation="Ensure RLS is enabled and policies are properly configured",
                    file=str(file_path),
                    line=line_number,
                    source=FindingSource.STATIC,
                    metadata={"table": table_name, "operation": operation}
                )
                
                findings.append(finding)
        
        # Check for service role usage in client code
        service_role_pattern = r"(?i)service[_-]?role[_-]?key"
        if re.search(service_role_pattern, content):
            line_number = content.find("service_role") + 1
            line_number = content[:content.find("service_role")].count('\n') + 1
            
            finding = SecurityFinding(
                id=f"supabase:service_role_usage:{file_path}:{content.find('service_role')}",
                title="Service role key usage in client code",
                severity=FindingSeverity.CRITICAL,
                confidence="HIGH",
                description="Service role key detected in client-side code",
                impact="Service role key in client code bypasses all RLS policies",
                recommendation="Remove service role key from client code and use anon key",
                file=str(file_path),
                line=line_number,
                source=FindingSource.STATIC
            )
            
            findings.append(finding)
        
        # Check for missing error handling
        if "supabase" in content.lower() and "createClient" in content:
            # Look for operations without error handling
            operations_pattern = r"\.(select|insert|update|delete|upsert)\s*\([^)]*\)(?!\s*\.(then|catch|finally))"
            matches = re.finditer(operations_pattern, content, re.IGNORECASE)
            
            for match in matches:
                line_number = content[:match.start()].count('\n') + 1
                
                finding = SecurityFinding(
                    id=f"supabase:missing_error_handling:{file_path}:{match.start()}",
                    title="Missing error handling for Supabase operation",
                    severity=FindingSeverity.LOW,
                    confidence="MEDIUM",
                    description="Supabase operation without proper error handling",
                    impact="Unhandled errors may expose sensitive information",
                    recommendation="Add proper error handling with try-catch or .catch()",
                    file=str(file_path),
                    line=line_number,
                    source=FindingSource.STATIC
                )
                
                findings.append(finding)
        
        return findings
    
    def _should_skip_file(self, file_path: Path) -> bool:
        """Check if file should be skipped during scanning."""
        skip_patterns = [
            ".git/",
            "node_modules/",
            ".venv/",
            "venv/",
            "__pycache__/",
            ".pytest_cache/",
            "*.pyc",
            "*.pyo",
            "*.pyd",
            "*.so",
            "*.dll",
            "*.exe",
            "*.bin",
            "*.jpg",
            "*.jpeg",
            "*.png",
            "*.gif",
            "*.ico",
            "*.svg",
            "*.pdf",
            "*.zip",
            "*.tar",
            "*.gz"
        ]
        
        file_str = str(file_path)
        for pattern in skip_patterns:
            if pattern.endswith("/") and pattern[:-1] in file_str:
                return True
            elif pattern.startswith("*") and file_str.endswith(pattern[1:]):
                return True
        
        return False
    
    def _is_binary_file(self, content: str) -> bool:
        """Check if file content is binary."""
        try:
            content.encode('utf-8')
            return False
        except UnicodeDecodeError:
            return True
