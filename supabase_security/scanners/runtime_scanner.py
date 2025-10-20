"""
Runtime security scanner for live Supabase endpoints.
"""

import requests
import socket
import subprocess
import shutil
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin, urlparse
import json
import time

from ..core.finding import SecurityFinding, FindingSeverity, FindingSource, get_compliance_mapping
from ..core.config import SecurityConfig


class RuntimeScanner:
    """Runtime security scanner for live Supabase endpoints."""
    
    def __init__(self, config: SecurityConfig):
        self.config = config
        self.session = requests.Session()
        self.session.timeout = self.config.scan_settings.timeout_seconds
    
    def scan_endpoints(self) -> List[SecurityFinding]:
        """Perform comprehensive runtime security scan."""
        findings = []
        
        if not self.config.supabase_config.project_url:
            return findings
        
        if not self.config.scan_settings.allow_external_scans:
            return findings
        
        try:
            # Parse the base URL
            base_url = self.config.supabase_config.project_url.rstrip('/')
            parsed_url = urlparse(base_url)
            host = parsed_url.hostname
            port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
            
            # Run various runtime checks
            findings.extend(self._check_graphql_introspection(base_url))
            findings.extend(self._check_rest_endpoints(base_url))
            findings.extend(self._check_auth_endpoints(base_url))
            findings.extend(self._check_port_scanning(host, port))
            findings.extend(self._check_ssl_configuration(base_url))
            findings.extend(self._check_headers_security(base_url))
            
        except Exception as e:
            findings.append(SecurityFinding(
                id="runtime:scan_error",
                title="Runtime scan failed",
                severity=FindingSeverity.MEDIUM,
                confidence="LOW",
                description=f"Error during runtime scan: {e}",
                impact="Unable to perform runtime security checks",
                recommendation="Check network connectivity and endpoint configuration",
                source=FindingSource.RUNTIME,
                metadata={"error": str(e)}
            ))
        
        return findings
    
    def _check_graphql_introspection(self, base_url: str) -> List[SecurityFinding]:
        """Check if GraphQL introspection is enabled."""
        findings = []
        
        try:
            graphql_url = urljoin(base_url, "/graphql/v1")
            
            # Test introspection query
            introspection_query = {
                "query": "query { __schema { types { name } } }"
            }
            
            response = self.session.post(
                graphql_url,
                json=introspection_query,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    if data.get("data", {}).get("__schema"):
                        findings.append(SecurityFinding(
                            id="runtime:graphql_introspection",
                            title="GraphQL introspection enabled",
                            severity=FindingSeverity.HIGH,
                            confidence="HIGH",
                            description="GraphQL introspection is enabled and accessible",
                            impact="Introspection exposes schema information to attackers",
                            recommendation="Disable GraphQL introspection in production",
                            source=FindingSource.RUNTIME,
                            metadata={"endpoint": graphql_url}
                        ))
                except json.JSONDecodeError:
                    pass
        
        except requests.exceptions.RequestException:
            pass  # Endpoint not accessible
        
        return findings
    
    def _check_rest_endpoints(self, base_url: str) -> List[SecurityFinding]:
        """Check REST API endpoints for security issues."""
        findings = []
        
        try:
            rest_url = urljoin(base_url, "/rest/v1")
            
            # Test unauthenticated access
            response = self.session.get(rest_url)
            
            if response.status_code == 200:
                findings.append(SecurityFinding(
                    id="runtime:rest_unauthenticated",
                    title="REST API accessible without authentication",
                    severity=FindingSeverity.MEDIUM,
                    confidence="MEDIUM",
                    description="REST API endpoint responds to unauthenticated requests",
                    impact="May expose data if RLS is not properly configured",
                    recommendation="Ensure proper authentication and RLS policies",
                    source=FindingSource.RUNTIME,
                    metadata={"endpoint": rest_url, "status_code": response.status_code}
                ))
            
            # Test for information disclosure
            if "supabase" in response.text.lower() or "postgrest" in response.text.lower():
                findings.append(SecurityFinding(
                    id="runtime:rest_info_disclosure",
                    title="REST API information disclosure",
                    severity=FindingSeverity.LOW,
                    confidence="MEDIUM",
                    description="REST API response contains system information",
                    impact="Information disclosure may help attackers",
                    recommendation="Configure API to not expose system information",
                    source=FindingSource.RUNTIME,
                    metadata={"endpoint": rest_url}
                ))
        
        except requests.exceptions.RequestException:
            pass  # Endpoint not accessible
        
        return findings
    
    def _check_auth_endpoints(self, base_url: str) -> List[SecurityFinding]:
        """Check authentication endpoints for security issues."""
        findings = []
        
        try:
            auth_url = urljoin(base_url, "/auth/v1")
            
            # Test auth endpoint accessibility
            response = self.session.get(auth_url)
            
            if response.status_code == 200:
                # Check for information disclosure
                if "supabase" in response.text.lower() or "gotrue" in response.text.lower():
                    findings.append(SecurityFinding(
                        id="runtime:auth_info_disclosure",
                        title="Auth endpoint information disclosure",
                        severity=FindingSeverity.LOW,
                        confidence="MEDIUM",
                        description="Auth endpoint exposes system information",
                        impact="Information disclosure may help attackers",
                        recommendation="Configure auth service to not expose system information",
                        source=FindingSource.RUNTIME,
                        metadata={"endpoint": auth_url}
                    ))
            
            # Test for user enumeration
            test_email = "nonexistent@example.com"
            signup_url = urljoin(auth_url, "/signup")
            
            signup_response = self.session.post(
                signup_url,
                json={"email": test_email, "password": "testpassword123"}
            )
            
            if signup_response.status_code in [200, 201]:
                findings.append(SecurityFinding(
                    id="runtime:user_enumeration",
                    title="User enumeration possible",
                    severity=FindingSeverity.MEDIUM,
                    confidence="MEDIUM",
                    description="Auth endpoint allows user enumeration",
                    impact="Attackers can determine if email addresses are registered",
                    recommendation="Implement rate limiting and consistent response times",
                    source=FindingSource.RUNTIME,
                    metadata={"endpoint": signup_url}
                ))
        
        except requests.exceptions.RequestException:
            pass  # Endpoint not accessible
        
        return findings
    
    def _check_port_scanning(self, host: str, port: int) -> List[SecurityFinding]:
        """Check for open ports on the target host."""
        findings = []
        
        # Default ports to check
        ports_to_check = self.config.scan_settings.default_ports.copy()
        if port not in ports_to_check:
            ports_to_check.append(port)
        
        open_ports = self._scan_ports(host, ports_to_check)
        
        for open_port in open_ports:
            severity = FindingSeverity.HIGH if open_port in [22, 5432, 54321, 54322] else FindingSeverity.MEDIUM
            
            findings.append(SecurityFinding(
                id=f"runtime:open_port:{open_port}",
                title=f"Open port {open_port} detected",
                severity=severity,
                confidence="HIGH",
                description=f"Port {open_port} is open and accessible",
                impact="Open ports increase attack surface",
                recommendation="Close unnecessary ports or restrict access",
                source=FindingSource.RUNTIME,
                metadata={"host": host, "port": open_port}
            ))
        
        return findings
    
    def _scan_ports(self, host: str, ports: List[int]) -> List[int]:
        """Scan for open ports on the target host."""
        open_ports = []
        
        # Try nmap first if available
        if shutil.which("nmap"):
            try:
                port_list = ",".join(str(p) for p in ports)
                result = subprocess.run(
                    ["nmap", "-Pn", "-p", port_list, "--open", "-T4", "-oG", "-", host],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.returncode == 0:
                    for line in result.stdout.splitlines():
                        if "Ports:" in line:
                            parts = line.split("Ports:")[1].strip()
                            for segment in parts.split(","):
                                segment = segment.strip()
                                if not segment:
                                    continue
                                fields = segment.split("/")
                                try:
                                    port_num = int(fields[0])
                                    state = fields[1].lower() if len(fields) > 1 else ""
                                    if state == "open":
                                        open_ports.append(port_num)
                                except (ValueError, IndexError):
                                    continue
                    
                    return sorted(set(open_ports))
            
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
                pass
        
        # Fallback to socket scanning
        for port in ports:
            if self._is_port_open(host, port):
                open_ports.append(port)
        
        return open_ports
    
    def _is_port_open(self, host: str, port: int, timeout: float = 1.0) -> bool:
        """Check if a port is open using socket connection."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((host, port))
                return result == 0
        except Exception:
            return False
    
    def _check_ssl_configuration(self, base_url: str) -> List[SecurityFinding]:
        """Check SSL/TLS configuration."""
        findings = []
        
        if not base_url.startswith("https://"):
            findings.append(SecurityFinding(
                id="runtime:no_ssl",
                title="No SSL/TLS encryption",
                severity=FindingSeverity.HIGH,
                confidence="HIGH",
                description="Connection is not using SSL/TLS encryption",
                impact="Data transmitted in plain text",
                recommendation="Enable HTTPS with proper SSL/TLS configuration",
                source=FindingSource.RUNTIME,
                metadata={"url": base_url}
            ))
            return findings
        
        try:
            # Test SSL configuration
            response = self.session.get(base_url, verify=True)
            
            # Check for weak SSL/TLS versions (simplified check)
            if hasattr(response.raw, 'version'):
                ssl_version = response.raw.version
                if ssl_version in ['TLSv1', 'TLSv1.1']:
                    findings.append(SecurityFinding(
                        id="runtime:weak_ssl",
                        title="Weak SSL/TLS version",
                        severity=FindingSeverity.MEDIUM,
                        confidence="MEDIUM",
                        description=f"Using weak SSL/TLS version: {ssl_version}",
                        impact="Weak SSL/TLS versions are vulnerable to attacks",
                        recommendation="Upgrade to TLS 1.2 or higher",
                        source=FindingSource.RUNTIME,
                        metadata={"ssl_version": ssl_version}
                    ))
        
        except requests.exceptions.SSLError as e:
            findings.append(SecurityFinding(
                id="runtime:ssl_error",
                title="SSL/TLS configuration error",
                severity=FindingSeverity.MEDIUM,
                confidence="HIGH",
                description=f"SSL/TLS error: {e}",
                impact="SSL/TLS configuration issues may affect security",
                recommendation="Fix SSL/TLS configuration",
                source=FindingSource.RUNTIME,
                metadata={"error": str(e)}
            ))
        
        return findings
    
    def _check_headers_security(self, base_url: str) -> List[SecurityFinding]:
        """Check HTTP security headers."""
        findings = []
        
        try:
            response = self.session.get(base_url)
            headers = response.headers
            
            # Check for missing security headers
            security_headers = {
                "Strict-Transport-Security": "HSTS header missing",
                "X-Content-Type-Options": "Content type sniffing protection missing",
                "X-Frame-Options": "Clickjacking protection missing",
                "X-XSS-Protection": "XSS protection header missing",
                "Content-Security-Policy": "Content Security Policy missing"
            }
            
            for header, description in security_headers.items():
                if header not in headers:
                    findings.append(SecurityFinding(
                        id=f"runtime:missing_header:{header.lower().replace('-', '_')}",
                        title=f"Missing security header: {header}",
                        severity=FindingSeverity.MEDIUM,
                        confidence="HIGH",
                        description=description,
                        impact="Missing security headers reduce protection against attacks",
                        recommendation=f"Add {header} header to responses",
                        source=FindingSource.RUNTIME,
                        metadata={"missing_header": header}
                    ))
            
            # Check for dangerous headers
            if "Server" in headers:
                server_info = headers["Server"]
                if "supabase" in server_info.lower() or "postgrest" in server_info.lower():
                    findings.append(SecurityFinding(
                        id="runtime:server_info_disclosure",
                        title="Server information disclosure",
                        severity=FindingSeverity.LOW,
                        confidence="MEDIUM",
                        description=f"Server header exposes system information: {server_info}",
                        impact="Information disclosure may help attackers",
                        recommendation="Configure server to not expose system information",
                        source=FindingSource.RUNTIME,
                        metadata={"server_header": server_info}
                    ))
        
        except requests.exceptions.RequestException:
            pass  # Endpoint not accessible
        
        return findings
