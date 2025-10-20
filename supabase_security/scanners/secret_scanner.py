"""
Enhanced secret detection with Git leak detection and Supabase-specific patterns.
"""

import re
import hashlib
import subprocess
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import Counter
import math
import json


class SecretScanner:
    """Advanced secret detection with Git leak detection capabilities."""
    
    def __init__(self, project_path: str):
        self.project_path = Path(project_path)
        self.git_available = shutil.which("git") is not None
        self.trufflehog_available = shutil.which("trufflehog") is not None
        
        # Supabase-specific secret patterns
        self.supabase_patterns = {
            "service_role_key": {
                "pattern": r"(?i)(?:sb_|supabase_)?service_role[_-]?key\s*[:=]\s*['\"]?([A-Za-z0-9\-_.]{20,})['\"]?",
                "severity": "CRITICAL",
                "description": "Supabase service role key detected",
                "impact": "Service role key provides full database access",
                "recommendation": "Remove from codebase and rotate the key immediately"
            },
            "anon_key": {
                "pattern": r"(?i)(?:sb_|supabase_)?anon[_-]?key\s*[:=]\s*['\"]?([A-Za-z0-9\-_.]{20,})['\"]?",
                "severity": "HIGH",
                "description": "Supabase anonymous key detected",
                "impact": "Anonymous key exposure may allow unauthorized access",
                "recommendation": "Remove from codebase and rotate the key"
            },
            "jwt_secret": {
                "pattern": r"(?i)(?:jwt_|supabase_)?jwt[_-]?secret\s*[:=]\s*['\"]?([A-Za-z0-9\-_.!@#$%^&*()_+]{8,})['\"]?",
                "severity": "CRITICAL",
                "description": "JWT secret detected",
                "impact": "JWT secret compromise allows token forgery",
                "recommendation": "Use strong random secret and rotate immediately"
            },
            "database_password": {
                "pattern": r"(?i)(?:db_|database_)?password\s*[:=]\s*['\"]?([A-Za-z0-9\-_.!@#$%^&*()_+]{8,})['\"]?",
                "severity": "HIGH",
                "description": "Database password detected",
                "impact": "Database password exposure allows direct database access",
                "recommendation": "Use environment variables or secret management"
            },
            "api_key": {
                "pattern": r"(?i)(?:api_|supabase_)?key\s*[:=]\s*['\"]?([A-Za-z0-9\-_.]{20,})['\"]?",
                "severity": "MEDIUM",
                "description": "API key detected",
                "impact": "API key exposure may allow unauthorized API access",
                "recommendation": "Move to environment variables or secret management"
            }
        }
        
        # Generic secret patterns
        self.generic_patterns = {
            "aws_access_key": {
                "pattern": r"(?i)aws[_-]?access[_-]?key[_-]?id\s*[:=]\s*['\"]?(AKIA[0-9A-Z]{16})['\"]?",
                "severity": "CRITICAL",
                "description": "AWS access key ID detected",
                "impact": "AWS credentials allow cloud resource access",
                "recommendation": "Rotate AWS credentials immediately"
            },
            "aws_secret_key": {
                "pattern": r"(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
                "severity": "CRITICAL",
                "description": "AWS secret access key detected",
                "impact": "AWS credentials allow cloud resource access",
                "recommendation": "Rotate AWS credentials immediately"
            },
            "github_token": {
                "pattern": r"(?i)(?:github_|gh_)?token\s*[:=]\s*['\"]?(ghp_[A-Za-z0-9]{36})['\"]?",
                "severity": "HIGH",
                "description": "GitHub personal access token detected",
                "impact": "GitHub token allows repository access",
                "recommendation": "Revoke and regenerate GitHub token"
            },
            "private_key": {
                "pattern": r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----",
                "severity": "CRITICAL",
                "description": "Private key detected",
                "impact": "Private key exposure allows authentication bypass",
                "recommendation": "Remove private key and regenerate"
            },
            "slack_token": {
                "pattern": r"(?i)(?:slack_)?token\s*[:=]\s*['\"]?(xox[baprs]-[0-9]{12}-[0-9]{12}-[A-Za-z0-9]{24})['\"]?",
                "severity": "HIGH",
                "description": "Slack token detected",
                "impact": "Slack token allows workspace access",
                "recommendation": "Revoke and regenerate Slack token"
            }
        }
        
        # Combine all patterns
        self.all_patterns = {**self.supabase_patterns, **self.generic_patterns}
    
    def scan_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Scan a single file for secrets."""
        findings = []
        
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            return findings
        
        # Skip binary files
        if self._is_binary_file(content):
            return findings
        
        # Scan for each pattern
        for pattern_name, pattern_info in self.all_patterns.items():
            matches = re.finditer(pattern_info["pattern"], content, re.MULTILINE)
            
            for match in matches:
                secret_value = match.group(1) if match.groups() else match.group(0)
                
                # Calculate entropy for additional validation
                entropy = self._calculate_entropy(secret_value)
                
                # Skip low entropy matches (likely false positives)
                if entropy < 3.0:
                    continue
                
                # Get line number
                line_number = content[:match.start()].count('\n') + 1
                
                finding = {
                    "id": f"secret:{pattern_name}:{file_path}:{match.start()}",
                    "title": pattern_info["description"],
                    "severity": pattern_info["severity"],
                    "confidence": self._calculate_confidence(entropy, pattern_name),
                    "description": f"Secret detected in {file_path.name} at line {line_number}",
                    "impact": pattern_info["impact"],
                    "recommendation": pattern_info["recommendation"],
                    "file": str(file_path),
                    "line": line_number,
                    "source": "secret_scan",
                    "metadata": {
                        "pattern_name": pattern_name,
                        "entropy": entropy,
                        "secret_length": len(secret_value),
                        "secret_preview": secret_value[:8] + "..." if len(secret_value) > 8 else secret_value
                    }
                }
                
                findings.append(finding)
        
        return findings
    
    def _is_binary_file(self, content: str) -> bool:
        """Check if file content is binary."""
        try:
            content.encode('utf-8')
            return False
        except UnicodeDecodeError:
            return True
    
    def _calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not data:
            return 0.0
        
        # Count character frequencies
        char_counts = Counter(data)
        length = len(data)
        
        # Calculate entropy
        entropy = 0.0
        for count in char_counts.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _calculate_confidence(self, entropy: float, pattern_name: str) -> str:
        """Calculate confidence level based on entropy and pattern."""
        if entropy >= 4.0:
            return "HIGH"
        elif entropy >= 3.5:
            return "MEDIUM"
        else:
            return "LOW"
    
    def scan_git_history(self) -> List[Dict[str, Any]]:
        """Scan Git history for secrets using git log."""
        findings = []
        
        if not self.git_available:
            return findings
        
        try:
            # Get list of files that have been committed
            result = subprocess.run(
                ["git", "log", "--name-only", "--pretty=format:", "--all"],
                cwd=self.project_path,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode != 0:
                return findings
            
            # Get unique file paths
            file_paths = set()
            for line in result.stdout.splitlines():
                if line.strip() and not line.startswith(' '):
                    file_paths.add(line.strip())
            
            # Scan each file in Git history
            for file_path in file_paths:
                full_path = self.project_path / file_path
                if full_path.exists() and full_path.is_file():
                    file_findings = self.scan_file(full_path)
                    for finding in file_findings:
                        finding["metadata"]["git_history"] = True
                    findings.extend(file_findings)
            
        except subprocess.TimeoutExpired:
            print("Git history scan timed out")
        except Exception as e:
            print(f"Error scanning Git history: {e}")
        
        return findings
    
    def scan_with_trufflehog(self) -> List[Dict[str, Any]]:
        """Scan using TruffleHog if available."""
        findings = []
        
        if not self.trufflehog_available:
            return findings
        
        try:
            # Run TruffleHog
            result = subprocess.run(
                ["trufflehog", "filesystem", str(self.project_path), "--json"],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode != 0:
                return findings
            
            # Parse TruffleHog output
            for line in result.stdout.splitlines():
                try:
                    data = json.loads(line)
                    
                    finding = {
                        "id": f"trufflehog:{data.get('DetectorName', 'unknown')}:{data.get('Raw', '')[:20]}",
                        "title": f"Secret detected by TruffleHog: {data.get('DetectorName', 'Unknown')}",
                        "severity": "HIGH",
                        "confidence": "HIGH",
                        "description": f"Secret detected in {data.get('SourceMetadata', {}).get('Data', {}).get('Filesystem', {}).get('file', 'unknown file')}",
                        "impact": "Secret exposure detected by specialized tool",
                        "recommendation": "Remove secret and rotate credentials",
                        "file": data.get('SourceMetadata', {}).get('Data', {}).get('Filesystem', {}).get('file'),
                        "line": data.get('SourceMetadata', {}).get('Data', {}).get('Filesystem', {}).get('line'),
                        "source": "trufflehog",
                        "metadata": {
                            "detector": data.get('DetectorName'),
                            "verified": data.get('Verified', False),
                            "raw_preview": data.get('Raw', '')[:20] + "..." if len(data.get('Raw', '')) > 20 else data.get('Raw', '')
                        }
                    }
                    
                    findings.append(finding)
                    
                except json.JSONDecodeError:
                    continue
                    
        except subprocess.TimeoutExpired:
            print("TruffleHog scan timed out")
        except Exception as e:
            print(f"Error running TruffleHog: {e}")
        
        return findings
    
    def scan_git_leaks(self) -> List[Dict[str, Any]]:
        """Scan for Git leaks using git log and diff."""
        findings = []
        
        if not self.git_available:
            return findings
        
        try:
            # Check for secrets in commit messages
            result = subprocess.run(
                ["git", "log", "--all", "--grep", "password", "--grep", "secret", "--grep", "key", "--oneline"],
                cwd=self.project_path,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0 and result.stdout.strip():
                finding = {
                    "id": "git:commit_message_secrets",
                    "title": "Potential secrets in commit messages",
                    "severity": "MEDIUM",
                    "confidence": "MEDIUM",
                    "description": "Commit messages contain keywords that may indicate secret exposure",
                    "impact": "Commit messages with secret keywords may indicate accidental exposure",
                    "recommendation": "Review commit messages and remove any exposed secrets",
                    "source": "git_leak_scan",
                    "metadata": {
                        "commit_count": len(result.stdout.strip().splitlines()),
                        "sample_commits": result.stdout.strip().splitlines()[:3]
                    }
                }
                findings.append(finding)
            
            # Check for large files that might contain secrets
            result = subprocess.run(
                ["git", "rev-list", "--objects", "--all", "|", "git", "cat-file", "--batch-check='%(objecttype) %(objectname) %(objectsize) %(rest)'", "|", "sed", "-n", "'s/^blob //p'", "|", "sort", "--numeric-sort", "--key=2", "|", "tail", "-10"],
                cwd=self.project_path,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0 and result.stdout.strip():
                large_files = []
                for line in result.stdout.strip().splitlines():
                    parts = line.split()
                    if len(parts) >= 3:
                        size = int(parts[1])
                        if size > 1024 * 1024:  # Files larger than 1MB
                            large_files.append({"hash": parts[0], "size": size})
                
                if large_files:
                    finding = {
                        "id": "git:large_files",
                        "title": "Large files in Git history",
                        "severity": "LOW",
                        "confidence": "LOW",
                        "description": f"Found {len(large_files)} large files in Git history",
                        "impact": "Large files may contain secrets or sensitive data",
                        "recommendation": "Review large files and consider using Git LFS or removing them",
                        "source": "git_leak_scan",
                        "metadata": {
                            "large_files": large_files
                        }
                    }
                    findings.append(finding)
            
        except subprocess.TimeoutExpired:
            print("Git leak scan timed out")
        except Exception as e:
            print(f"Error scanning Git leaks: {e}")
        
        return findings
    
    def scan_project(self, include_git_history: bool = True, use_trufflehog: bool = True) -> List[Dict[str, Any]]:
        """Comprehensive secret scan of the project."""
        findings = []
        
        # Scan current files
        for file_path in self.project_path.rglob("*"):
            if file_path.is_file() and not self._should_skip_file(file_path):
                file_findings = self.scan_file(file_path)
                findings.extend(file_findings)
        
        # Scan Git history if requested
        if include_git_history:
            git_findings = self.scan_git_history()
            findings.extend(git_findings)
            
            git_leak_findings = self.scan_git_leaks()
            findings.extend(git_leak_findings)
        
        # Use TruffleHog if available and requested
        if use_trufflehog and self.trufflehog_available:
            trufflehog_findings = self.scan_with_trufflehog()
            findings.extend(trufflehog_findings)
        
        # Remove duplicates based on file and line
        unique_findings = self._deduplicate_findings(findings)
        
        return unique_findings
    
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
    
    def _deduplicate_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate findings based on file, line, and pattern."""
        seen = set()
        unique_findings = []
        
        for finding in findings:
            # Create a key based on file, line, and pattern
            key = (
                finding.get("file", ""),
                finding.get("line", 0),
                finding.get("metadata", {}).get("pattern_name", "")
            )
            
            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)
        
        return unique_findings
    
    def get_secret_statistics(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate statistics about secret findings."""
        if not findings:
            return {"total": 0, "by_severity": {}, "by_type": {}}
        
        by_severity = Counter(f["severity"] for f in findings)
        by_type = Counter(f["metadata"].get("pattern_name", "unknown") for f in findings)
        
        # Calculate risk score
        severity_scores = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 10, "LOW": 5, "INFO": 1}
        total_risk = sum(severity_scores.get(f["severity"], 1) for f in findings)
        
        return {
            "total": len(findings),
            "by_severity": dict(by_severity),
            "by_type": dict(by_type),
            "risk_score": total_risk,
            "high_risk_count": len([f for f in findings if f["severity"] in ["CRITICAL", "HIGH"]]),
            "supabase_secrets": len([f for f in findings if f["metadata"].get("pattern_name", "").startswith("supabase")])
        }
