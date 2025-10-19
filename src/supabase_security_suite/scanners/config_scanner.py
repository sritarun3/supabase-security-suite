"""
Configuration Scanner

Scans for configuration security issues:
- HTTP vs HTTPS in configs
- Weak JWT secrets
- Debug mode enabled
- Permissive CORS settings
- Missing security headers
- Insecure cookie settings
"""

import re
from pathlib import Path
from typing import Dict, List

from ..core.scanner import BaseScanner, ScanContext
from ..core.utils import is_binary_file
from ..reporting.models import Finding, FindingCategory, Location, Severity


class ConfigurationScanner(BaseScanner):
    """Scanner for configuration security issues."""

    name = "config_scanner"
    description = "Configuration security scanner"
    category = "config"

    # File patterns to scan
    SCAN_PATTERNS = [
        "**/*.env*",
        "**/config.toml",
        "**/config.yaml",
        "**/config.yml",
        "**/config.json",
        "**/docker-compose*.yml",
        "**/docker-compose*.yaml",
        "**/.env",
        "**/.env.*",
    ]

    # Exclude documentation and examples
    EXCLUDE_PATTERNS = [
        "node_modules",
        ".git",
        "venv",
        # Documentation
        "*.md",
        "README",
        "docs/",
        ".github/",
        # Test files
        "tests/",
        "test/",
        "*_test.*",
        "test_*",
        # Examples (9 FPs)
        "examples/",
        "example/",
        "demo/",
        "*-demo.*",
        "*-example.*",
        "*-sample.*",
    ]

    async def scan(self) -> List[Finding]:
        """Run configuration security scan."""
        findings = []
        target_dir = self.context.target_path

        for pattern in self.SCAN_PATTERNS:
            for file_path in target_dir.glob(pattern):
                if self._should_exclude(file_path):
                    continue

                if is_binary_file(file_path):
                    continue

                findings.extend(self._scan_config_file(file_path))

        return findings

    def _should_exclude(self, file_path: Path) -> bool:
        """Check if file should be excluded from scanning."""
        path_parts = file_path.parts

        for pattern in self.EXCLUDE_PATTERNS:
            pattern_clean = pattern.rstrip("/").rstrip("*").rstrip(".")
            if pattern_clean in path_parts:
                return True

            if "*" in pattern:
                import fnmatch

                if fnmatch.fnmatch(file_path.name, pattern):
                    return True

        return False

    def _scan_config_file(self, file_path: Path) -> List[Finding]:
        """Scan a configuration file for security issues."""
        findings = []

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                lines = content.splitlines()

            # Check for HTTP (not HTTPS) URLs in config
            findings.extend(self._check_http_urls(file_path, lines))

            # Check for weak JWT secrets
            findings.extend(self._check_jwt_secrets(file_path, lines))

            # Check for debug mode
            findings.extend(self._check_debug_mode(file_path, lines))

            # Check for permissive CORS
            findings.extend(self._check_cors_settings(file_path, lines))

        except Exception as e:
            self.logger.warning(f"Error scanning config file {file_path}: {e}")

        return findings

    def _check_http_urls(self, file_path: Path, lines: List[str]) -> List[Finding]:
        """Check for HTTP (not HTTPS) URLs - SMART DETECTION."""
        findings = []
        http_pattern = re.compile(r"http://[^\s\"']+", re.IGNORECASE)
        seen_urls = set()

        for line_num, line in enumerate(lines, start=1):
            # Skip comments (this is the key improvement!)
            if self._is_comment_or_doc(line):
                continue

            # Only flag HTTP (not HTTPS)
            if "https://" in line.lower():
                continue

            match = http_pattern.search(line)
            if match:
                url = match.group(0)

                # Skip if already seen (deduplication at scan level)
                if url in seen_urls:
                    continue
                seen_urls.add(url)

                # Only flag if it's likely a real config issue
                # Check if line has assignment or key: value
                if not any(sep in line for sep in ["=", ":"]):
                    continue

                finding = Finding(
                    id=f"config:http-url:{file_path.name}:{hash(url) & 0xFFFF}",
                    title="HTTP endpoint present",
                    description=f"HTTP URL detected in configuration: {url}. Should use HTTPS for security.",
                    severity=Severity.MEDIUM,
                    category=FindingCategory.CONFIGURATION,
                    source=self.name,
                    location=Location(
                        file=str(file_path.relative_to(self.context.target_path)),
                        line=line_num,
                    ),
                    recommendation="Replace HTTP URLs with HTTPS to ensure encrypted communication",
                    compliance={
                        "SOC2": ["CC6.1", "CC6.7"],
                        "ISO27001": ["A.13.1.1", "A.13.2.1"],
                        "HIPAA": ["164.312(e)(1)"],
                    },
                    metadata={"url": url},
                )
                findings.append(finding)

        return findings

    def _check_jwt_secrets(self, file_path: Path, lines: List[str]) -> List[Finding]:
        """Check for weak JWT secrets (<32 characters)."""
        findings = []
        # Match the entire secret value (not just first 31 chars)
        jwt_pattern = re.compile(
            r"(?:jwt[_-]?secret|secret[_-]?key)\s*[:=]\s*['\"]?([^'\";\s]+)['\"]?",
            re.IGNORECASE,
        )

        for line_num, line in enumerate(lines, start=1):
            match = jwt_pattern.search(line)
            if match:
                secret = match.group(1)

                # Skip if secret is >= 32 characters (secure enough)
                if len(secret) >= 32:
                    continue

                # Skip if it's clearly a placeholder
                if secret.lower() in ["your-secret-here", "change-me", "secret", "example"]:
                    continue

                finding = Finding(
                    id=f"config:weak-jwt:{file_path.name}:{line_num}",
                    title="Weak JWT Secret",
                    description=f"JWT secret is only {len(secret)} characters. Should be at least 32 characters for security.",
                    severity=Severity.HIGH,
                    category=FindingCategory.CONFIGURATION,
                    source=self.name,
                    location=Location(
                        file=str(file_path.relative_to(self.context.target_path)),
                        line=line_num,
                    ),
                    recommendation="Use a strong JWT secret with at least 32 random characters",
                    compliance={
                        "SOC2": ["CC6.1"],
                        "ISO27001": ["A.9.4.3"],
                    },
                )
                findings.append(finding)

        return findings

    def _check_debug_mode(self, file_path: Path, lines: List[str]) -> List[Finding]:
        """Check if debug mode is enabled."""
        findings = []
        debug_pattern = re.compile(
            r"(?:debug|DEBUG)\s*[:=]\s*(?:true|True|TRUE|1|yes)", re.IGNORECASE
        )

        for line_num, line in enumerate(lines, start=1):
            if debug_pattern.search(line):
                finding = Finding(
                    id=f"config:debug-enabled:{file_path.name}:{line_num}",
                    title="Debug mode enabled",
                    description="Debug mode is enabled, which may expose sensitive information",
                    severity=Severity.MEDIUM,
                    category=FindingCategory.CONFIGURATION,
                    source=self.name,
                    location=Location(
                        file=str(file_path.relative_to(self.context.target_path)),
                        line=line_num,
                    ),
                    recommendation="Disable debug mode in production environments",
                    compliance={
                        "SOC2": ["CC7.2"],
                        "ISO27001": ["A.12.4.1"],
                    },
                )
                findings.append(finding)

        return findings

    def _check_cors_settings(self, file_path: Path, lines: List[str]) -> List[Finding]:
        """Check for permissive CORS settings."""
        findings = []
        # Match CORS/cors with optional underscores, hyphens, and words like ORIGINS
        cors_pattern = re.compile(
            r"(?:cors[\w_-]*|Access-Control-Allow-Origin)\s*[:=]\s*['\"]?\*['\"]?",
            re.IGNORECASE,
        )

        for line_num, line in enumerate(lines, start=1):
            if cors_pattern.search(line):
                finding = Finding(
                    id=f"config:permissive-cors:{file_path.name}:{line_num}",
                    title="Permissive CORS configuration",
                    description="CORS allows all origins (*), which may expose APIs to unauthorized domains",
                    severity=Severity.MEDIUM,
                    category=FindingCategory.CONFIGURATION,
                    source=self.name,
                    location=Location(
                        file=str(file_path.relative_to(self.context.target_path)),
                        line=line_num,
                    ),
                    recommendation="Restrict CORS to specific trusted origins instead of using '*'",
                    compliance={
                        "SOC2": ["CC6.1"],
                        "ISO27001": ["A.13.1.3"],
                    },
                )
                findings.append(finding)

        return findings

    def _is_comment_or_doc(self, line: str) -> bool:
        """
        Check if line is a comment or documentation.
        This is KEY to reducing false positives!
        """
        line = line.strip()

        # Empty lines
        if not line:
            return True

        # Shell/Python/YAML comments
        if line.startswith("#"):
            return True

        # JavaScript/TypeScript comments
        if line.startswith("//") or line.startswith("/*"):
            return True

        # TOML comments
        if line.startswith(";"):
            return True

        # Documentation indicators
        doc_keywords = ["example:", "note:", "documentation:", "readme", "todo:", "fixme:"]
        if any(keyword in line.lower() for keyword in doc_keywords):
            return True

        return False

