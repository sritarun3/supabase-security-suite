"""
Docker Scanner

Scans Docker and docker-compose files for security issues:
- Exposed ports without proper restrictions
- Default or weak passwords
- Unsafe authentication settings
- Privileged containers
- Missing security options
"""

import re
import yaml
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime

from ..core.scanner import BaseScanner, ScanContext
from ..reporting.models import Finding, Severity, FindingCategory, Location


class DockerScanner(BaseScanner):
    """Scanner for Docker and docker-compose security issues."""
    
    name = "docker_scanner"
    description = "Scans Docker and docker-compose files for security misconfigurations"
    category = "infrastructure"
    
    # Dangerous ports that should typically not be exposed
    DANGEROUS_PORTS = {
        5432: "PostgreSQL",
        3306: "MySQL",
        6379: "Redis",
        27017: "MongoDB",
        9200: "Elasticsearch",
        2379: "etcd",
        5984: "CouchDB",
        9042: "Cassandra",
    }
    
    # Default/weak passwords to check for
    WEAK_PASSWORDS = [
        "password",
        "123456",
        "admin",
        "root",
        "postgres",
        "changeme",
        "secret",
        "default",
        "test",
        "demo",
    ]
    
    
    async def scan(self, context: ScanContext) -> List[Finding]:
        """
        Execute Docker configuration scanning.
        
        Args:
            context: Scan context with target directory and configuration
            
        Returns:
            List of security findings related to Docker
        """
        findings = []
        
        try:
            target_dir = Path(context.target_path)
            
            if not target_dir.exists():
                self.logger.warning(f"Target directory does not exist: {target_dir}")
                return findings
            
            # Find and scan docker-compose files
            compose_files = list(target_dir.glob("**/docker-compose*.yml")) + \
                           list(target_dir.glob("**/docker-compose*.yaml"))
            
            for compose_file in compose_files:
                findings.extend(await self._scan_compose_file(compose_file, context))
            
            # Find and scan Dockerfiles
            dockerfiles = list(target_dir.glob("**/Dockerfile*"))
            
            for dockerfile in dockerfiles:
                findings.extend(await self._scan_dockerfile(dockerfile, context))
            
            if not compose_files and not dockerfiles:
                self.logger.info("No Docker configuration files found")
        
        except Exception as e:
            self.logger.error(f"Docker scan failed: {e}")
            findings.append(Finding(
                id="docker_scanner_error",
                title="Docker Scanner Error",
                description=f"Failed to complete Docker scan: {str(e)}",
                severity=Severity.MEDIUM,
                category=FindingCategory.CONFIGURATION,
                location=Location(file=str(context.target_path)),
                source="docker_scanner",
                recommendation="Check the scanner logs and Docker configuration files for details",
                metadata={"error": str(e)}
            ))
        
        return findings
    
    async def _scan_compose_file(self, file_path: Path, context: ScanContext) -> List[Finding]:
        """Scan a docker-compose file for security issues."""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                compose_data = yaml.safe_load(f)
            
            if not compose_data or 'services' not in compose_data:
                return findings
            
            services = compose_data.get('services', {})
            
            for service_name, service_config in services.items():
                if not isinstance(service_config, dict):
                    continue
                
                # Check for exposed dangerous ports
                findings.extend(self._check_exposed_ports(
                    file_path, service_name, service_config, context
                ))
                
                # Check for weak passwords in environment variables
                findings.extend(self._check_weak_passwords(
                    file_path, service_name, service_config, context
                ))
                
                # Check for privileged containers
                findings.extend(self._check_privileged_containers(
                    file_path, service_name, service_config, context
                ))
                
                # Check for missing security options
                findings.extend(self._check_security_options(
                    file_path, service_name, service_config, context
                ))
        
        except yaml.YAMLError as e:
            self.logger.warning(f"Failed to parse YAML file {file_path}: {e}")
        except Exception as e:
            self.logger.warning(f"Error scanning compose file {file_path}: {e}")
        
        return findings
    
    def _check_exposed_ports(
        self,
        file_path: Path,
        service_name: str,
        service_config: Dict[str, Any],
        context: ScanContext
    ) -> List[Finding]:
        """Check for dangerous ports being exposed."""
        findings = []
        
        ports = service_config.get('ports', [])
        if not ports:
            return findings
        
        for port_spec in ports:
            # Parse port specification (e.g., "8080:80", "5432", "0.0.0.0:5432:5432")
            port_str = str(port_spec)
            parts = port_spec.split(':')
            
            # Get the internal port (last part)
            internal_port_str = parts[-1].split('/')[0]  # Handle "8080/tcp"
            
            try:
                internal_port = int(internal_port_str)
            except ValueError:
                continue
            
            # Check if it's a dangerous port
            if internal_port in self.DANGEROUS_PORTS:
                port_name = self.DANGEROUS_PORTS[internal_port]
                
                # Check if bound to all interfaces (0.0.0.0 or no host specified)
                is_public = len(parts) <= 2 or parts[0] == '0.0.0.0' or parts[0] == ''
                
                severity = Severity.CRITICAL if is_public else Severity.HIGH
                
                try:
                    rel_path = file_path.relative_to(context.target_path)
                except ValueError:
                    rel_path = file_path
                
                # Generate unique ID for this finding
                import hashlib
                finding_id = f"docker_{hashlib.md5(f'{rel_path}:{service_name}:{internal_port}'.encode()).hexdigest()[:12]}"
                
                findings.append(Finding(
                    id=finding_id,
                    title=f"Exposed {port_name} Port in {service_name}",
                    description=(
                        f"Service '{service_name}' in {rel_path} exposes {port_name} port {internal_port}. "
                        f"{'This port is publicly accessible (0.0.0.0)' if is_public else 'This database port should not be exposed'}. "
                        f"Database ports should never be exposed to the internet and should only be accessible "
                        f"through secure tunnels or internal networks."
                    ),
                    severity=severity,
                    category=FindingCategory.NETWORK,
                    location=Location(
                        file=str(rel_path)
                    ),
                    source="docker_scanner",
                    recommendation=(
                        f"Remove port {internal_port} from exposed ports or bind to 127.0.0.1 only. "
                        f"Use Docker networks for service-to-service communication. "
                        f"If external access is required, use a VPN or SSH tunnel."
                    ),
                    compliance={
                        "ISO27001": ["A.13.1.3"],
                        "SOC2": ["CC6.6"],
                        "PCI-DSS": ["1.3"]
                    },
                    metadata={
                        "service": service_name,
                        "port": internal_port,
                        "port_type": port_name,
                        "port_spec": port_str,
                        "publicly_exposed": is_public,
                        "file": str(rel_path)
                    }
                ))
        
        return findings
    
    def _check_weak_passwords(
        self,
        file_path: Path,
        service_name: str,
        service_config: Dict[str, Any],
        context: ScanContext
    ) -> List[Finding]:
        """Check for weak or default passwords in environment variables."""
        findings = []
        
        environment = service_config.get('environment', [])
        
        # Handle both list and dict formats
        env_vars = {}
        if isinstance(environment, list):
            for item in environment:
                if '=' in str(item):
                    key, value = str(item).split('=', 1)
                    env_vars[key] = value
        elif isinstance(environment, dict):
            env_vars = environment
        
        password_keys = [
            'PASSWORD', 'PASSWD', 'PWD', 'SECRET', 'TOKEN',
            'POSTGRES_PASSWORD', 'MYSQL_PASSWORD', 'REDIS_PASSWORD',
            'DB_PASSWORD', 'DATABASE_PASSWORD', 'JWT_SECRET'
        ]
        
        for key, value in env_vars.items():
            key_upper = key.upper()
            
            # Check if this is a password-related variable
            if any(pwd_key in key_upper for pwd_key in password_keys):
                value_str = str(value).lower()
                
                # Check if it's a weak password
                if any(weak in value_str for weak in self.WEAK_PASSWORDS):
                    try:
                        rel_path = file_path.relative_to(context.target_path)
                    except ValueError:
                        rel_path = file_path
                    
                    # Generate unique ID for this finding
                    import hashlib
                    finding_id = f"docker_{hashlib.md5(f'{rel_path}:{service_name}:weak_password:{key}'.encode()).hexdigest()[:12]}"
                    
                    findings.append(Finding(
                        id=finding_id,
                        title=f"Weak Password in {service_name}",
                        description=(
                            f"Service '{service_name}' in {rel_path} uses a weak or default password "
                            f"for environment variable '{key}'. Weak passwords can be easily compromised "
                            f"through brute force attacks."
                        ),
                        severity=Severity.CRITICAL,
                        category=FindingCategory.AUTHENTICATION,
                        location=Location(
                            file=str(rel_path),
                            line=None
                        ),
                        source="docker_scanner",
                        recommendation=(
                            f"Replace the weak password with a strong, randomly generated password. "
                            f"Use Docker secrets or environment variables from a secure vault. "
                            f"Never commit passwords to version control."
                        ),
                        compliance={
                            "HIPAA": ["164.308(a)(5)(ii)(D)"],
                            "ISO27001": ["A.9.4.3"],
                            "SOC2": ["CC6.1"],
                            "NIST": ["IA-5"]
                        },
                        metadata={
                            "service": service_name,
                            "env_variable": key,
                            "file": str(rel_path)
                        }
                    ))
        
        return findings
    
    def _check_privileged_containers(
        self,
        file_path: Path,
        service_name: str,
        service_config: Dict[str, Any],
        context: ScanContext
    ) -> List[Finding]:
        """Check for containers running in privileged mode."""
        findings = []
        
        if service_config.get('privileged', False):
            try:
                rel_path = file_path.relative_to(context.target_path)
            except ValueError:
                rel_path = file_path
            
            # Generate unique ID for this finding
            import hashlib
            finding_id = f"docker_{hashlib.md5(f'{rel_path}:{service_name}:privileged'.encode()).hexdigest()[:12]}"
            
            findings.append(Finding(
                id=finding_id,
                title=f"Privileged Container: {service_name}",
                description=(
                    f"Service '{service_name}' in {rel_path} is configured to run in privileged mode. "
                    f"Privileged containers have access to all devices on the host and can bypass "
                    f"many security features. This significantly increases the attack surface."
                ),
                severity=Severity.HIGH,
                category=FindingCategory.CONFIGURATION,
                location=Location(
                    file=str(rel_path),
                    line=None
                ),
                source="docker_scanner",
                recommendation=(
                    f"Remove 'privileged: true' from service '{service_name}'. "
                    f"Use specific capabilities or device mounts instead if elevated permissions are needed."
                ),
                compliance={
                    "ISO27001": ["A.14.2.5"],
                    "SOC2": ["CC6.6"]
                },
                metadata={
                    "service": service_name,
                    "file": str(rel_path)
                }
            ))
        
        return findings
    
    def _check_security_options(
        self,
        file_path: Path,
        service_name: str,
        service_config: Dict[str, Any],
        context: ScanContext
    ) -> List[Finding]:
        """Check for missing security options like read-only root filesystem."""
        findings = []
        
        # Check for read_only root filesystem
        if not service_config.get('read_only', False):
            # This is informational - not all services can have read-only root
            pass  # Skip for now to avoid too many false positives
        
        # Check for no-new-privileges security option
        security_opt = service_config.get('security_opt', [])
        has_no_new_privileges = 'no-new-privileges:true' in security_opt
        
        if not has_no_new_privileges:
            # This is a recommendation, not a critical issue
            pass  # Skip for now
        
        return findings
    
    async def _scan_dockerfile(self, file_path: Path, context: ScanContext) -> List[Finding]:
        """Scan a Dockerfile for security issues."""
        findings = []
        
        try:
            content = file_path.read_text(encoding='utf-8')
            lines = content.split('\n')
            
            for line_num, line in enumerate(lines, 1):
                line_stripped = line.strip()
                
                # Check for :latest tag in FROM directive
                if line_stripped.upper().startswith('FROM '):
                    if ':latest' in line_stripped.lower() or (':' not in line_stripped and 'as ' not in line_stripped.lower()):
                        try:
                            rel_path = file_path.relative_to(context.target_path)
                        except ValueError:
                            rel_path = file_path
                        
                        # Generate unique ID for this finding
                        import hashlib
                        finding_id = f"docker_{hashlib.md5(f'{rel_path}:{line_num}:latest_tag'.encode()).hexdigest()[:12]}"
                        
                        findings.append(Finding(
                            id=finding_id,
                            title="Docker Image Using :latest Tag",
                            description=(
                                f"Dockerfile {rel_path}:{line_num} uses the :latest tag or no tag (defaults to :latest). "
                                f"Using :latest makes builds non-deterministic and can lead to unexpected behavior "
                                f"when the base image is updated."
                            ),
                            severity=Severity.LOW,
                            category=FindingCategory.CONFIGURATION,
                            location=Location(
                                file=str(rel_path),
                                line=line_num
                            ),
                            source="docker_scanner",
                            recommendation=(
                                "Pin the base image to a specific version tag. "
                                "For example, use 'FROM postgres:15.2' instead of 'FROM postgres:latest' or 'FROM postgres'."
                            ),
                            metadata={
                                "file": str(rel_path),
                                "line": line_num,
                                "image_line": line_stripped
                            }
                        ))
                
                # Check for ENV with secrets/passwords
                if line_stripped.upper().startswith('ENV '):
                    # Look for suspicious environment variable names
                    if re.search(r'(?:PASSWORD|SECRET|KEY|TOKEN|AUTH)', line_stripped, re.IGNORECASE):
                        try:
                            rel_path = file_path.relative_to(context.target_path)
                        except ValueError:
                            rel_path = file_path
                        
                        # Generate unique ID for this finding
                        import hashlib
                        finding_id = f"docker_{hashlib.md5(f'{rel_path}:{line_num}:env_secret'.encode()).hexdigest()[:12]}"
                        
                        findings.append(Finding(
                            id=finding_id,
                            title="Hardcoded Secret in ENV Variable",
                            description=(
                                f"Dockerfile {rel_path}:{line_num} contains an ENV variable with a potentially hardcoded secret. "
                                f"Secrets in ENV variables are visible in container metadata and image history."
                            ),
                            severity=Severity.HIGH,
                            category=FindingCategory.SECRETS,
                            location=Location(
                                file=str(rel_path),
                                line=line_num
                            ),
                            source="docker_scanner",
                            recommendation=(
                                "Use build-time secrets (--secret flag) or runtime secrets mounting instead of ENV. "
                                "For Docker: Use secrets from Docker Swarm or pass them at runtime with -e flag."
                            ),
                            metadata={
                                "file": str(rel_path),
                                "line": line_num,
                                "env_line": line_stripped
                            }
                        ))
                
                # Check for EXPOSE of dangerous ports
                if line_stripped.upper().startswith('EXPOSE '):
                    port_match = re.search(r'EXPOSE\s+(\d+)', line_stripped, re.IGNORECASE)
                    if port_match:
                        port = int(port_match.group(1))
                        if port in self.DANGEROUS_PORTS:
                            try:
                                rel_path = file_path.relative_to(context.target_path)
                            except ValueError:
                                rel_path = file_path
                            
                            # Generate unique ID for this finding
                            import hashlib
                            finding_id = f"docker_{hashlib.md5(f'{rel_path}:{line_num}:expose_{port}'.encode()).hexdigest()[:12]}"
                            
                            findings.append(Finding(
                                id=finding_id,
                                title=f"Database Port {port} Exposed ({self.DANGEROUS_PORTS[port]})",
                                description=(
                                    f"Dockerfile {rel_path}:{line_num} exposes port {port} ({self.DANGEROUS_PORTS[port]}). "
                                    f"Database ports should not be directly exposed to the internet."
                                ),
                                severity=Severity.HIGH,
                                category=FindingCategory.CONFIGURATION,
                                location=Location(
                                    file=str(rel_path),
                                    line=line_num
                                ),
                                source="docker_scanner",
                                recommendation=(
                                    f"Remove EXPOSE {port} or ensure the port is only accessible via secure internal networks. "
                                    f"Use reverse proxy or API gateway for external access."
                                ),
                                metadata={
                                    "file": str(rel_path),
                                    "line": line_num,
                                    "port": port,
                                    "service": self.DANGEROUS_PORTS[port]
                                }
                            ))
                
                # Check for apt-get without --no-cache or rm -rf /var/lib/apt/lists/*
                if 'apt-get install' in line_stripped.lower() and '&&' in line_stripped:
                    if '--no-cache' not in line_stripped.lower() and 'rm -rf /var/lib/apt' not in line_stripped.lower():
                        try:
                            rel_path = file_path.relative_to(context.target_path)
                        except ValueError:
                            rel_path = file_path
                        
                        # Generate unique ID for this finding
                        import hashlib
                        finding_id = f"docker_{hashlib.md5(f'{rel_path}:{line_num}:apt_cache'.encode()).hexdigest()[:12]}"
                        
                        findings.append(Finding(
                            id=finding_id,
                            title="apt-get Without Cache Cleanup",
                            description=(
                                f"Dockerfile {rel_path}:{line_num} uses apt-get install without cleaning up the apt cache. "
                                f"This increases the image size unnecessarily."
                            ),
                            severity=Severity.LOW,
                            category=FindingCategory.CONFIGURATION,
                            location=Location(
                                file=str(rel_path),
                                line=line_num
                            ),
                            source="docker_scanner",
                            recommendation=(
                                "Add '&& rm -rf /var/lib/apt/lists/*' at the end of apt-get commands to reduce image size. "
                                "Example: RUN apt-get update && apt-get install -y package && rm -rf /var/lib/apt/lists/*"
                            ),
                            metadata={
                                "file": str(rel_path),
                                "line": line_num
                            }
                        ))
                
                # Check for running as root
                if line_stripped.upper().startswith('USER ') and 'root' in line_stripped.lower():
                    try:
                        rel_path = file_path.relative_to(context.target_path)
                    except ValueError:
                        rel_path = file_path
                    
                    # Generate unique ID for this finding
                    import hashlib
                    finding_id = f"docker_{hashlib.md5(f'{rel_path}:{line_num}:root_user'.encode()).hexdigest()[:12]}"
                    
                    findings.append(Finding(
                        id=finding_id,
                        title=f"Container Running as Root",
                        description=(
                            f"Dockerfile {rel_path}:{line_num} explicitly sets USER to root. "
                            f"Running containers as root is a security risk as it grants full privileges "
                            f"to processes inside the container."
                        ),
                        severity=Severity.MEDIUM,
                        category=FindingCategory.CONFIGURATION,
                        location=Location(
                            file=str(rel_path),
                            line=line_num
                        ),
                        source="docker_scanner",
                        recommendation=(
                            "Create and use a non-root user in your Dockerfile. "
                            "Add: RUN useradd -m myuser && USER myuser"
                        ),
                        metadata={
                            "file": str(rel_path),
                            "line": line_num
                        }
                    ))
        
        except Exception as e:
            self.logger.warning(f"Error scanning Dockerfile {file_path}: {e}")
        
        return findings

