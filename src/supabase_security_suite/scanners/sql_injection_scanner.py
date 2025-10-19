"""
SQL Injection Scanner

Scans code for potential SQL injection vulnerabilities:
- String concatenation in SQL queries
- Unsafe use of user input in queries
- Missing parameterization
- Dynamic query construction
"""

import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Pattern
from datetime import datetime

from ..core.scanner import BaseScanner, ScanContext
from ..core.utils import is_binary_file
from ..reporting.models import Finding, Severity, FindingCategory, Location


class SQLInjectionScanner(BaseScanner):
    """Scanner for SQL injection vulnerabilities in code."""
    
    name = "sql_injection_scanner"
    description = "Scans code for potential SQL injection vulnerabilities"
    category = "code"
    
    # Patterns for detecting potential SQL injection
    SQL_INJECTION_PATTERNS: List[Dict[str, Any]] = [
        {
            "name": "string_concatenation",
            "pattern": re.compile(
                r'(query|sql|statement)\s*[=+]\s*["\'].*?\+.*?["\']',
                re.IGNORECASE
            ),
            "severity": Severity.HIGH,
            "description": "String concatenation in SQL query"
        },
        {
            "name": "f_string_sql",
            "pattern": re.compile(
                r'f["\'].*?(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER).*?\{.*?\}.*?["\']',
                re.IGNORECASE
            ),
            "severity": Severity.HIGH,
            "description": "F-string used in SQL query with variable interpolation"
        },
        {
            "name": "format_sql",
            "pattern": re.compile(
                r'["\'].*?(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER).*?["\']\.format\(',
                re.IGNORECASE
            ),
            "severity": Severity.HIGH,
            "description": "String format() used in SQL query"
        },
        {
            "name": "percent_format_sql",
            "pattern": re.compile(
                r'["\'].*?(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER).*?%s.*?["\'].*?%.*?\(',
                re.IGNORECASE
            ),
            "severity": Severity.MEDIUM,
            "description": "% formatting used in SQL query (check if parameterized)"
        },
        {
            "name": "execute_with_concat",
            "pattern": re.compile(
                r'(execute|exec|query)\s*\(\s*["\'].*?\+.*?["\']',
                re.IGNORECASE
            ),
            "severity": Severity.CRITICAL,
            "description": "SQL execution with string concatenation"
        },
        {
            "name": "template_string_sql",
            "pattern": re.compile(
                r'`.*?(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER).*?\$\{.*?\}.*?`',
                re.IGNORECASE
            ),
            "severity": Severity.HIGH,
            "description": "Template string used in SQL query (JavaScript/TypeScript)"
        },
    ]
    
    # File extensions to scan
    SCAN_EXTENSIONS = [
        '.py', '.js', '.ts', '.tsx', '.jsx',
        '.java', '.php', '.rb', '.go', '.cs'
    ]
    
    # Directories to exclude
    EXCLUDE_DIRS = [
        'node_modules', '.git', 'venv', 'env',
        '.venv', '__pycache__', 'dist', 'build',
        '.next', '.cache', 'coverage'
    ]
    
    
    async def scan(self, context: ScanContext) -> List[Finding]:
        """
        Execute SQL injection vulnerability scanning.
        
        Args:
            context: Scan context with target directory and configuration
            
        Returns:
            List of security findings related to SQL injection
        """
        findings = []
        
        try:
            target_dir = Path(context.target_path)
            
            if not target_dir.exists():
                self.logger.warning(f"Target directory does not exist: {target_dir}")
                return findings
            
            # Scan code files
            scanned_files = 0
            for ext in self.SCAN_EXTENSIONS:
                for file_path in target_dir.glob(f"**/*{ext}"):
                    # Skip excluded directories
                    if any(exclude in file_path.parts for exclude in self.EXCLUDE_DIRS):
                        continue
                    
                    if not file_path.is_file() or is_binary_file(str(file_path)):
                        continue
                    
                    try:
                        findings.extend(await self._scan_file(file_path, context))
                        scanned_files += 1
                    except Exception as e:
                        self.logger.warning(f"Failed to scan file {file_path}: {e}")
            
            self.logger.info(f"Scanned {scanned_files} files for SQL injection")
        
        except Exception as e:
            self.logger.error(f"SQL injection scan failed: {e}")
            findings.append(Finding(
                title="SQL Injection Scanner Error",
                description=f"Failed to complete SQL injection scan: {str(e)}",
                severity=Severity.MEDIUM,
                category=FindingCategory.CONFIGURATION,
                location=Location(type="filesystem", path=str(context.target_path)),
                source="sql_injection_scanner",
                timestamp=datetime.utcnow(),
                metadata={"error": str(e)}
            ))
        
        return findings
    
    async def _scan_file(self, file_path: Path, context: ScanContext) -> List[Finding]:
        """Scan a single file for SQL injection vulnerabilities."""
        findings = []
        
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            lines = content.split('\n')
            
            for line_num, line in enumerate(lines, 1):
                # Skip comments
                if self._is_comment_line(line, file_path.suffix):
                    continue
                
                # Check each pattern
                for pattern_def in self.SQL_INJECTION_PATTERNS:
                    matches = pattern_def['pattern'].finditer(line)
                    
                    for match in matches:
                        # Skip if it looks like a safe parameterized query
                        if self._is_likely_safe(line, match, file_path.suffix):
                            continue
                        
                        try:
                            rel_path = file_path.relative_to(context.target_path)
                        except ValueError:
                            rel_path = file_path
                        
                        findings.append(Finding(
                            title=f"Potential SQL Injection: {pattern_def['description']}",
                            description=(
                                f"Potential SQL injection vulnerability detected in {rel_path}:{line_num}. "
                                f"{pattern_def['description']}. "
                                f"Dynamic SQL query construction without proper parameterization "
                                f"can allow attackers to manipulate queries and access unauthorized data."
                            ),
                            severity=pattern_def['severity'],
                            category=FindingCategory.INPUT_VALIDATION,
                            location=Location(
                                type="file",
                                path=str(rel_path),
                                line=line_num
                            ),
                            source="sql_injection_scanner",
                            timestamp=datetime.utcnow(),
                            recommendation=(
                                "Use parameterized queries or prepared statements instead of string concatenation. "
                                "For Python: use cursor.execute(query, (param1, param2)). "
                                "For JavaScript: use parameterized queries with $1, $2, etc."
                            ),
                            compliance_mappings={
                                "OWASP": "A03:2021 – Injection",
                                "CWE": "CWE-89",
                                "SANS": "Top 25"
                            },
                            metadata={
                                "file": str(rel_path),
                                "line": line_num,
                                "pattern": pattern_def['name'],
                                "matched_text": match.group(0)[:100]  # Limit length
                            }
                        ))
        
        except Exception as e:
            self.logger.warning(f"Error scanning file {file_path}: {e}")
        
        return findings
    
    def _is_comment_line(self, line: str, file_ext: str) -> bool:
        """Check if line is a comment."""
        line_stripped = line.strip()
        
        if file_ext in ['.py', '.sh', '.rb']:
            return line_stripped.startswith('#')
        elif file_ext in ['.js', '.ts', '.tsx', '.jsx', '.java', '.go', '.cs', '.php']:
            return line_stripped.startswith('//') or line_stripped.startswith('/*')
        
        return False
    
    def _is_likely_safe(self, line: str, match: re.Match, file_ext: str) -> bool:
        """Check if the match is likely a safe parameterized query."""
        # Check for common safe patterns
        safe_indicators = [
            r'\$\d+',  # PostgreSQL parameters ($1, $2, etc.)
            r'\?',     # Question mark parameters
            r':\w+',   # Named parameters (:param)
            r'%\(\w+\)s',  # Python dict parameters %(name)s
        ]
        
        context = line[max(0, match.start()-50):min(len(line), match.end()+50)]
        
        for indicator in safe_indicators:
            if re.search(indicator, context):
                return True
        
        # Check for specific safe functions/methods
        safe_functions = [
            'execute(',  # When used with parameters as second argument
            'query(',
            'prepared',
            'parameterized',
        ]
        
        for func in safe_functions:
            if func in context.lower():
                # Check if there are multiple arguments (indicates parameterization)
                if context.count(',') > 0:
                    return True
        
        return False

