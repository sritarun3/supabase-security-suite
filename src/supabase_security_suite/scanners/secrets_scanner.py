"""
Secrets Scanner

Scans for exposed secrets and API keys:
- High-entropy strings (potential secrets)
- Pattern matching for known secret formats
- Git history scanning for leaked secrets
- Environment files and configuration files
"""

import re
import os
from pathlib import Path
from typing import List, Dict, Any, Optional, Pattern
from datetime import datetime

from ..core.scanner import BaseScanner, ScanContext
from ..core.utils import calculate_entropy, is_binary_file
from ..reporting.models import Finding, Severity, FindingCategory, Location


class SecretsScanner(BaseScanner):
    """Scanner for exposed secrets and API keys."""
    
    name = "secrets_scanner"
    description = "Scans for exposed secrets, API keys, and high-entropy strings"
    category = "secrets"
    
    # Patterns for known secret formats
    SECRET_PATTERNS: Dict[str, Pattern] = {
        "supabase_service_role": re.compile(
            r'eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}(?:\.[A-Za-z0-9_-]{20,})?',
            re.IGNORECASE
        ),
        "supabase_anon_key": re.compile(
            r'eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}(?:\.[A-Za-z0-9_-]{20,})?',
            re.IGNORECASE
        ),
        "jwt_secret": re.compile(
            r'(?:jwt[_-]?secret|secret[_-]?key)\s*[:=]\s*["\']?([A-Za-z0-9+/=]{32,})["\']?',
            re.IGNORECASE
        ),
        "postgres_password": re.compile(
            r'(?:postgres|database)[_-]?(?:password|pwd)\s*[:=]\s*["\']?([^\s"\']{8,})["\']?',
            re.IGNORECASE
        ),
        "password": re.compile(
            r'\bpassword\s*=\s*["\']([^"\']{8,})["\']',
            re.IGNORECASE
        ),
        "api_key": re.compile(
            r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']?([A-Za-z0-9_-]{8,})["\']?',
            re.IGNORECASE
        ),
        "aws_access_key": re.compile(
            r'(?:AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
            re.IGNORECASE
        ),
        "github_token": re.compile(
            r'ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|ghu_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}',
            re.IGNORECASE
        ),
        "stripe_key": re.compile(
            r'(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}',
            re.IGNORECASE
        ),
        "generic_secret": re.compile(
            r'(?:secret|passwd|pwd|token|auth)[_-]?\w*\s*[:=]\s*["\']([A-Za-z0-9+/=!@#$%^&*()]{12,})["\']',
            re.IGNORECASE
        ),
    }
    
    # File patterns to scan
    SCAN_PATTERNS = [
        "**/*.env*",
        "**/*.config.js",
        "**/*.config.ts",
        "**/*.yml",
        "**/*.yaml",
        "**/*.json",
        "**/*.sh",
        "**/*.py",
        "**/*.ts",
        "**/*.js",
        "**/*.sql",
        "**/docker-compose*.yml",
        "**/docker-compose*.yaml",
    ]
    
    # Files/directories to exclude
    EXCLUDE_PATTERNS = [
        "node_modules",
        ".git",
        "venv",
        "env",
        ".venv",
        "__pycache__",
        "dist",
        "build",
        ".next",
        ".cache",
        "coverage",
        # Documentation (37 FPs)
        "README.md",
        "README",
        "*.md",
        "docs/",
        ".github/",
        # Test files (5 FPs)
        "tests/",
        "test/",
        "*_test.py",
        "*_test.js",
        "*_test.ts",
        "test_*.py",
        "test_*.js",
        "test_*.ts",
        "*.test.py",
        "*.test.js",
        "*.test.ts",
        "test*.sh",
        # Examples/demos (9 FPs)
        "examples/",
        "example/",
        "sample/",
        "samples/",
        "demo/",
        "demos/",
        "*-demo.env",
        "*-example.env",
        "*-sample.env",
        "*_demo.*",
        "*_example.*",
        "*_sample.*",
        ".pytest_cache",
    ]
    
    def __init__(self, context: ScanContext):
        super().__init__(context)
        self.entropy_threshold = 4.5  # Shannon entropy threshold
    
    async def scan(self, context: ScanContext) -> List[Finding]:
        """
        Execute secrets scanning.
        
        Args:
            context: Scan context with target directory and configuration
            
        Returns:
            List of security findings related to secrets
        """
        findings = []
        
        try:
            target_dir = Path(context.target_path)
            
            if not target_dir.exists():
                self.logger.warning(f"Target directory does not exist: {target_dir}")
                return findings
            
            # Scan files for secrets
            findings.extend(await self._scan_files(target_dir, context))
            
            # Optionally scan git history
            if context.config.scanners.secrets.scan_git_history:
                findings.extend(await self._scan_git_history(target_dir, context))
        
        except Exception as e:
            self.logger.error(f"Secrets scan failed: {e}")
            findings.append(Finding(
                id="secrets_scanner_error",
                title="Secrets Scanner Error",
                description=f"Failed to complete secrets scan: {str(e)}",
                severity=Severity.HIGH,
                category=FindingCategory.CONFIGURATION,
                location=Location(file=str(context.target_path)),
                source="secrets_scanner",
                recommendation="Check the scanner logs and configuration for details",
                metadata={"error": str(e)}
            ))
        
        return findings
    
    async def _scan_files(self, target_dir: Path, context: ScanContext) -> List[Finding]:
        """Scan files in target directory for secrets."""
        findings = []
        scanned_files = 0
        
        # Combine default and context exclude patterns
        all_exclude_patterns = self.EXCLUDE_PATTERNS + context.exclude_patterns
        
        for pattern in self.SCAN_PATTERNS:
            for file_path in target_dir.glob(pattern):
                # Skip excluded directories and files
                skip_file = False
                for exclude_pattern in all_exclude_patterns:
                    # For directory patterns (ending with /), check path components
                    if exclude_pattern.endswith('/'):
                        dir_name = exclude_pattern.rstrip('/')
                        if dir_name in file_path.parts:
                            skip_file = True
                            break
                    # For directory wildcard patterns like "vendor/*", check if dir is in path
                    elif '/*' in exclude_pattern or '/**' in exclude_pattern:
                        dir_name = exclude_pattern.rstrip('/*').rstrip('*')
                        if dir_name in file_path.parts:
                            skip_file = True
                            break
                    # For filename wildcard patterns, match against filename
                    elif '*' in exclude_pattern:
                        from fnmatch import fnmatch
                        if fnmatch(file_path.name, exclude_pattern):
                            skip_file = True
                            break
                    # For exact filenames, check name match
                    else:
                        if file_path.name == exclude_pattern or exclude_pattern in file_path.parts:
                            skip_file = True
                            break
                
                if skip_file:
                    continue
                
                # Skip binary files
                if not file_path.is_file() or is_binary_file(str(file_path)):
                    continue
                
                try:
                    findings.extend(await self._scan_file(file_path, context))
                    scanned_files += 1
                except Exception as e:
                    self.logger.warning(f"Failed to scan file {file_path}: {e}")
        
        self.logger.info(f"Scanned {scanned_files} files for secrets")
        return findings
    
    async def _scan_file(self, file_path: Path, context: ScanContext) -> List[Finding]:
        """Scan a single file for secrets."""
        findings = []
        
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            lines = content.split('\n')
            
            for line_num, line in enumerate(lines, 1):
                # Check pattern matches
                for secret_type, pattern in self.SECRET_PATTERNS.items():
                    matches = pattern.finditer(line)
                    for match in matches:
                        findings.append(self._create_secret_finding(
                            file_path=file_path,
                            line_num=line_num,
                            line_content=line,
                            secret_type=secret_type,
                            match=match,
                            context=context
                        ))
                
                # Check high-entropy strings
                entropy_findings = self._check_line_entropy(
                    file_path, line_num, line, context
                )
                findings.extend(entropy_findings)
        
        except Exception as e:
            self.logger.warning(f"Error scanning file {file_path}: {e}")
        
        return findings
    
    def _create_secret_finding(
        self,
        file_path: Path,
        line_num: int,
        line_content: str,
        secret_type: str,
        match: re.Match,
        context: ScanContext
    ) -> Finding:
        """Create a finding for a detected secret."""
        
        # Determine severity based on secret type
        severity_map = {
            "supabase_service_role": Severity.CRITICAL,
            "supabase_anon_key": Severity.HIGH,
            "jwt_secret": Severity.CRITICAL,
            "postgres_password": Severity.CRITICAL,
            "api_key": Severity.HIGH,
            "aws_access_key": Severity.CRITICAL,
            "github_token": Severity.CRITICAL,
            "stripe_key": Severity.CRITICAL,
            "generic_secret": Severity.MEDIUM,
        }
        
        severity = severity_map.get(secret_type, Severity.HIGH)
        
        # Redact the secret in the description
        secret_value = match.group(0)
        redacted = secret_value[:4] + "*" * (len(secret_value) - 8) + secret_value[-4:]
        
        # Get relative path
        try:
            rel_path = file_path.relative_to(context.target_path)
        except ValueError:
            rel_path = file_path
        
        # Generate unique ID based on file path and line number
        import hashlib
        finding_id = f"secrets_{hashlib.md5(f'{rel_path}:{line_num}:{secret_type}'.encode()).hexdigest()[:12]}"
        
        return Finding(
            id=finding_id,
            title=f"{secret_type.replace('_', ' ').title()} Leak",
            description=(
                f"Pattern indicates a {secret_type.replace('_', ' ')} present in {rel_path}:{line_num}. "
                f"Exposed secrets can grant unauthorized access to your infrastructure."
            ),
            severity=severity,
            category=FindingCategory.SECRETS,
            location=Location(
                file=str(rel_path),
                line=line_num
            ),
            source="secrets_scanner",
            recommendation=(
                f"Remove from repo; move to secret manager; rotate the key. "
                f"Never commit secrets to version control."
            ),
            compliance={
                "HIPAA": ["164.312(a)(1)"],
                "ISO27001": ["A.9.2.4"],
                "SOC2": ["CC6.2"]
            },
            metadata={
                "secret_type": secret_type,
                "file": str(rel_path),
                "line": line_num,
                "redacted_value": redacted,
                "matched_pattern": secret_type
            }
        )
    
    def _check_line_entropy(
        self,
        file_path: Path,
        line_num: int,
        line: str,
        context: ScanContext
    ) -> List[Finding]:
        """Check line for high-entropy strings that might be secrets."""
        findings = []
        
        # Extract potential secret strings (quoted strings, assignment values)
        string_patterns = [
            r'["\']([A-Za-z0-9+/=!@#$%^&*()]{20,})["\']',  # Quoted strings
            r'=\s*([A-Za-z0-9+/=!@#$%^&*()]{20,})(?:\s|$)',  # Assignment values
        ]
        
        for pattern in string_patterns:
            matches = re.finditer(pattern, line)
            for match in matches:
                candidate = match.group(1)
                
                # Skip if it looks like a known non-secret pattern
                if self._is_likely_not_secret(candidate):
                    continue
                
                entropy = calculate_entropy(candidate)
                
                if entropy >= self.entropy_threshold:
                    try:
                        rel_path = file_path.relative_to(context.target_path)
                    except ValueError:
                        rel_path = file_path
                    
                    redacted = candidate[:4] + "*" * (len(candidate) - 8) + candidate[-4:]
                    
                    findings.append(Finding(
                        title=f"High-Entropy String in {rel_path.name}",
                        description=(
                            f"High-entropy string detected in {rel_path}:{line_num}. "
                            f"Entropy: {entropy:.2f} (threshold: {self.entropy_threshold}). "
                            f"This may indicate a hardcoded secret or API key."
                        ),
                        severity=Severity.MEDIUM,
                        category=FindingCategory.SECRETS,
                        location=Location(
                            file=str(rel_path),
                            line=line_num
                        ),
                        source="secrets_scanner",
                        recommendation=(
                            "Review this string. If it's a secret, move it to environment variables "
                            "or a secret management system."
                        ),
                        metadata={
                            "entropy": entropy,
                            "threshold": self.entropy_threshold,
                            "redacted_value": redacted,
                            "file": str(rel_path),
                            "line": line_num
                        }
                    ))
        
        return findings
    
    def _is_likely_not_secret(self, candidate: str) -> bool:
        """Check if string is likely not a secret (e.g., common constants, URLs)."""
        # Skip URLs
        if candidate.startswith(('http://', 'https://', 'www.')):
            return True
        
        # Skip common placeholder values
        placeholders = [
            'your-api-key',
            'your-secret',
            'changeme',
            'example',
            'localhost',
            'test-key',
            'dummy',
        ]
        
        candidate_lower = candidate.lower()
        if any(placeholder in candidate_lower for placeholder in placeholders):
            return True
        
        # Skip if too many repeating characters
        if len(set(candidate)) < len(candidate) * 0.3:
            return True
        
        return False
    
    async def _scan_git_history(self, target_dir: Path, context: ScanContext) -> List[Finding]:
        """Scan git history for leaked secrets (simplified version)."""
        findings = []
        
        git_dir = target_dir / ".git"
        if not git_dir.exists():
            self.logger.info("No git repository found, skipping git history scan")
            return findings
        
        self.logger.info("Git history scanning is a placeholder - use tools like gitleaks or truffleHog")
        
        # This is a placeholder - in production, you'd integrate with tools like:
        # - gitleaks
        # - truffleHog
        # - git-secrets
        
        return findings

