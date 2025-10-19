"""
Static Analysis Scanner

Scans for insecure code patterns and anti-patterns:
- Hardcoded credentials in source code
- Insecure function usage (eval, exec)
- Weak cryptography (MD5, SHA1)
- Hardcoded IPs and secrets
- Dangerous imports
"""

import re
from pathlib import Path
from typing import Any, Dict, List, Pattern

from ..core.scanner import BaseScanner, ScanContext
from ..core.utils import is_binary_file
from ..reporting.models import Finding, FindingCategory, Location, Severity


class StaticAnalysisScanner(BaseScanner):
    """Scanner for static code security anti-patterns."""

    name = "static_scanner"
    description = "Static analysis for code security issues"
    category = "static"

    # Insecure patterns to detect
    INSECURE_PATTERNS: Dict[str, Dict[str, Any]] = {
        "eval_usage": {
            "regex": re.compile(r"\beval\s*\(", re.IGNORECASE),
            "severity": Severity.HIGH,
            "title": "Dangerous eval() usage detected",
            "description": "Using eval() can lead to code injection vulnerabilities",
            "recommendation": "Avoid eval(). Use safe alternatives like json.loads() or ast.literal_eval()",
        },
        "exec_usage": {
            "regex": re.compile(r"\bexec\s*\(", re.IGNORECASE),
            "severity": Severity.HIGH,
            "title": "Dangerous exec() usage detected",
            "description": "Using exec() can lead to code injection vulnerabilities",
            "recommendation": "Avoid exec(). Refactor to use safe, explicit function calls",
        },
        "md5_usage": {
            "regex": re.compile(r"\bhashlib\.md5\(|\bMD5\(", re.IGNORECASE),
            "severity": Severity.MEDIUM,
            "title": "Weak cryptographic hash (MD5) detected",
            "description": "MD5 is cryptographically broken and should not be used for security",
            "recommendation": "Use SHA-256 or stronger: hashlib.sha256()",
        },
        "sha1_usage": {
            "regex": re.compile(r"\bhashlib\.sha1\(|\bSHA1\(", re.IGNORECASE),
            "severity": Severity.MEDIUM,
            "title": "Weak cryptographic hash (SHA1) detected",
            "description": "SHA1 is deprecated and should not be used for security",
            "recommendation": "Use SHA-256 or stronger: hashlib.sha256()",
        },
        "hardcoded_ip": {
            "regex": re.compile(
                r"(?:=|:|return)\s*['\"](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})['\"]"
            ),
            "severity": Severity.LOW,
            "title": "Hardcoded IP address detected",
            "description": "Hardcoded IP addresses make configuration inflexible",
            "recommendation": "Use environment variables or configuration files for IP addresses",
        },
        "hardcoded_password": {
            "regex": re.compile(
                r"(?:password|passwd|pwd)\s*=\s*['\"]([^'\"]{8,})['\"]",
                re.IGNORECASE,
            ),
            "severity": Severity.CRITICAL,
            "title": "Hardcoded password detected",
            "description": "Password found hardcoded in source code",
            "recommendation": "Use environment variables or secure secret management",
        },
        "sql_concat": {
            "regex": re.compile(r"(?:SELECT|INSERT|UPDATE|DELETE).*\+\s*['\"]", re.IGNORECASE),
            "severity": Severity.HIGH,
            "title": "Potential SQL injection via string concatenation",
            "description": "Building SQL queries with string concatenation is dangerous",
            "recommendation": "Use parameterized queries or ORM methods",
        },
        "pickle_usage": {
            "regex": re.compile(r"\bpickle\.loads?\(", re.IGNORECASE),
            "severity": Severity.HIGH,
            "title": "Insecure deserialization (pickle) detected",
            "description": "Pickle can execute arbitrary code during deserialization",
            "recommendation": "Use JSON or other safe serialization formats",
        },
    }

    # File patterns to scan
    SCAN_PATTERNS = ["**/*.py", "**/*.js", "**/*.ts", "**/*.jsx", "**/*.tsx"]

    # Directories to exclude (same as secrets scanner)
    EXCLUDE_PATTERNS = [
        "node_modules",
        ".git",
        "venv",
        "env",
        ".venv",
        "__pycache__",
        "dist",
        "build",
        # Documentation
        "*.md",
        "docs/",
        # Test files
        "tests/",
        "test/",
        "*_test.*",
        "test_*",
        # Examples
        "examples/",
        "example/",
        "demo/",
    ]

    async def scan(self) -> List[Finding]:
        """Run static analysis on source code files."""
        findings = []
        target_dir = self.context.target_path

        for pattern in self.SCAN_PATTERNS:
            for file_path in target_dir.glob(pattern):
                if self._should_exclude(file_path):
                    continue

                if is_binary_file(file_path):
                    continue

                findings.extend(self._scan_file(file_path))

        return findings

    def _should_exclude(self, file_path: Path) -> bool:
        """Check if file should be excluded from scanning."""
        path_parts = file_path.parts

        for pattern in self.EXCLUDE_PATTERNS:
            # Check if pattern is in path parts (directories)
            pattern_clean = pattern.rstrip("/").rstrip("*").rstrip(".")
            if pattern_clean in path_parts:
                return True

            # Check wildcard patterns against filename only
            if "*" in pattern:
                import fnmatch

                if fnmatch.fnmatch(file_path.name, pattern):
                    return True

        return False

    def _scan_file(self, file_path: Path) -> List[Finding]:
        """Scan a single file for insecure patterns."""
        findings = []

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            for line_num, line in enumerate(lines, start=1):
                # Skip comments
                if self._is_comment(line, file_path.suffix):
                    continue

                for pattern_name, pattern_info in self.INSECURE_PATTERNS.items():
                    regex = pattern_info["regex"]
                    if regex.search(line):
                        # Create finding
                        finding = Finding(
                            id=f"static:{pattern_name}:{file_path.name}:{line_num}",
                            title=pattern_info["title"],
                            description=pattern_info["description"],
                            severity=pattern_info["severity"],
                            category=FindingCategory.STATIC,
                            source=self.name,
                            location=Location(
                                file=str(file_path.relative_to(self.context.target_path)),
                                line=line_num,
                            ),
                            recommendation=pattern_info["recommendation"],
                            compliance={
                                "SOC2": ["CC6.1"],
                                "ISO27001": ["A.14.2.5"],
                            },
                        )
                        findings.append(finding)

        except Exception as e:
            self.logger.warning(f"Error scanning file {file_path}: {e}")

        return findings

    def _is_comment(self, line: str, file_ext: str) -> bool:
        """Check if line is a comment."""
        line = line.strip()

        # Python comments
        if file_ext in [".py"]:
            return line.startswith("#")

        # JavaScript/TypeScript comments
        if file_ext in [".js", ".ts", ".jsx", ".tsx"]:
            return line.startswith("//") or line.startswith("/*")

        return False

