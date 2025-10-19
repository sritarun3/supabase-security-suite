"""
Unit tests for scanners.docker_scanner module.
"""

import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch, mock_open

from supabase_security_suite.scanners.docker_scanner import DockerScanner
from supabase_security_suite.core.scanner import ScanContext
from supabase_security_suite.reporting.models import Severity, FindingCategory


class TestDockerScanner:
    """Tests for DockerScanner."""
    
    def test_scanner_initialization(self, scan_context):
        """Test Docker scanner initialization."""
        scanner = DockerScanner(scan_context)
        
        assert scanner.name == "docker_scanner"
        assert "docker" in scanner.description.lower()
        assert scanner.category == "infrastructure"
    
    @pytest.mark.asyncio
    async def test_scan_no_dockerfile(self, scan_context, tmp_path):
        """Test scanning directory with no Dockerfile."""
        context = ScanContext(
            config=scan_context.config,
            target_path=str(tmp_path),
        )
        
        scanner = DockerScanner(context)
        findings = await scanner.scan(context)
        
        # Should return empty or informational finding
        assert isinstance(findings, list)
    
    @pytest.mark.asyncio
    async def test_scan_root_user(self, scan_context, tmp_path):
        """Test detecting root user in Dockerfile."""
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("""
FROM postgres:15
COPY app /app
USER root
CMD ["postgres"]
        """)
        
        context = ScanContext(
            config=scan_context.config,
            target_path=str(tmp_path),
        )
        
        scanner = DockerScanner(context)
        findings = await scanner.scan(context)
        
        # Should detect root user
        root_findings = [f for f in findings if "root" in f.description.lower() or "user" in f.description.lower()]
        assert len(root_findings) > 0
        
        if root_findings:
            assert root_findings[0].severity in [Severity.HIGH, Severity.MEDIUM]
            assert root_findings[0].category == FindingCategory.CONFIGURATION
    
    @pytest.mark.asyncio
    async def test_scan_latest_tag(self, scan_context, tmp_path):
        """Test detecting use of 'latest' tag."""
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("""
FROM postgres:latest
WORKDIR /app
COPY . .
        """)
        
        context = ScanContext(
            config=scan_context.config,
            target_path=str(tmp_path),
        )
        
        scanner = DockerScanner(context)
        findings = await scanner.scan(context)
        
        # Should warn about latest tag
        latest_findings = [f for f in findings if "latest" in f.description.lower()]
        assert len(latest_findings) > 0
    
    @pytest.mark.asyncio
    async def test_scan_exposed_secrets(self, scan_context, tmp_path):
        """Test detecting exposed secrets in Dockerfile."""
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("""
FROM postgres:15
ENV DATABASE_PASSWORD=secret123
ENV API_KEY=sk-1234567890abcdef
USER postgres
        """)
        
        context = ScanContext(
            config=scan_context.config,
            target_path=str(tmp_path),
        )
        
        scanner = DockerScanner(context)
        findings = await scanner.scan(context)
        
        # Should detect hardcoded secrets in ENV
        secret_findings = [f for f in findings if "secret" in f.description.lower() or "password" in f.description.lower() or "env" in f.description.lower()]
        assert len(secret_findings) > 0
        
        if secret_findings:
            assert secret_findings[0].severity in [Severity.CRITICAL, Severity.HIGH]
    
    @pytest.mark.asyncio
    async def test_scan_exposed_ports(self, scan_context, tmp_path):
        """Test detecting exposed ports."""
        scan_context.config.scanners.docker.check_exposed_ports = True
        
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("""
FROM postgres:15
EXPOSE 5432
EXPOSE 8080
USER postgres
        """)
        
        context = ScanContext(
            config=scan_context.config,
            target_path=str(tmp_path),
        )
        
        scanner = DockerScanner(context)
        findings = await scanner.scan(context)
        
        # Should detect exposed ports
        port_findings = [f for f in findings if "port" in f.description.lower() or "expose" in f.description.lower()]
        assert len(port_findings) > 0
    
    @pytest.mark.asyncio
    async def test_scan_apt_get_no_cache(self, scan_context, tmp_path):
        """Test detecting apt-get without cache cleanup."""
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("""
FROM postgres:15
RUN apt-get update && apt-get install -y curl
USER postgres
        """)
        
        context = ScanContext(
            config=scan_context.config,
            target_path=str(tmp_path),
        )
        
        scanner = DockerScanner(context)
        findings = await scanner.scan(context)
        
        # Should warn about apt cache
        cache_findings = [f for f in findings if "apt" in f.description.lower() or "cache" in f.description.lower()]
        assert len(cache_findings) > 0
    
    @pytest.mark.asyncio
    async def test_scan_good_dockerfile(self, scan_context, tmp_path):
        """Test scanning a well-configured Dockerfile."""
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("""
FROM postgres:15-alpine
RUN apk add --no-cache curl
USER postgres
EXPOSE 5432
CMD ["postgres"]
        """)
        
        context = ScanContext(
            config=scan_context.config,
            target_path=str(tmp_path),
        )
        
        scanner = DockerScanner(context)
        findings = await scanner.scan(context)
        
        # Should have fewer or no critical findings
        critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical_findings) == 0
    
    @pytest.mark.asyncio
    async def test_scan_docker_compose(self, scan_context, tmp_path):
        """Test scanning docker-compose.yml."""
        compose_file = tmp_path / "docker-compose.yml"
        compose_file.write_text("""
version: '3.8'
services:
  db:
    image: postgres:15
    environment:
      POSTGRES_PASSWORD: hardcoded_password
    ports:
      - "5432:5432"
        """)
        
        context = ScanContext(
            config=scan_context.config,
            target_path=str(tmp_path),
        )
        
        scanner = DockerScanner(context)
        findings = await scanner.scan(context)
        
        # Should detect hardcoded password in compose file
        compose_findings = [f for f in findings if f.location and "compose" in f.location.file.lower()]
        assert len(compose_findings) > 0
    
    @pytest.mark.asyncio
    async def test_scan_multiple_stages(self, scan_context, tmp_path):
        """Test multi-stage Dockerfile."""
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("""
FROM node:18 as builder
WORKDIR /app
COPY package*.json ./
RUN npm install

FROM postgres:15
COPY --from=builder /app /app
USER postgres
        """)
        
        context = ScanContext(
            config=scan_context.config,
            target_path=str(tmp_path),
        )
        
        scanner = DockerScanner(context)
        findings = await scanner.scan(context)
        
        # Should handle multi-stage builds
        assert isinstance(findings, list)
    
    @pytest.mark.asyncio
    async def test_scan_add_vs_copy(self, scan_context, tmp_path):
        """Test detecting ADD instead of COPY."""
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("""
FROM postgres:15
ADD app.tar.gz /app/
USER postgres
        """)
        
        context = ScanContext(
            config=scan_context.config,
            target_path=str(tmp_path),
        )
        
        scanner = DockerScanner(context)
        findings = await scanner.scan(context)
        
        # Should recommend COPY over ADD
        add_findings = [f for f in findings if "add" in f.description.lower() or "copy" in f.description.lower()]
        assert len(add_findings) > 0
    
    @pytest.mark.asyncio
    async def test_scan_privileged_mode(self, scan_context, tmp_path):
        """Test detecting privileged mode in compose."""
        compose_file = tmp_path / "docker-compose.yml"
        compose_file.write_text("""
version: '3.8'
services:
  db:
    image: postgres:15
    privileged: true
        """)
        
        context = ScanContext(
            config=scan_context.config,
            target_path=str(tmp_path),
        )
        
        scanner = DockerScanner(context)
        findings = await scanner.scan(context)
        
        # Should flag privileged mode
        priv_findings = [f for f in findings if "privileged" in f.description.lower()]
        assert len(priv_findings) > 0
        if priv_findings:
            assert priv_findings[0].severity in [Severity.CRITICAL, Severity.HIGH]
    
    @pytest.mark.asyncio
    async def test_scan_healthcheck_missing(self, scan_context, tmp_path):
        """Test detecting missing HEALTHCHECK."""
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("""
FROM postgres:15
USER postgres
CMD ["postgres"]
        """)
        
        context = ScanContext(
            config=scan_context.config,
            target_path=str(tmp_path),
        )
        
        scanner = DockerScanner(context)
        findings = await scanner.scan(context)
        
        # Should recommend healthcheck
        health_findings = [f for f in findings if "health" in f.description.lower()]
        assert len(health_findings) > 0
    
    @pytest.mark.asyncio
    async def test_finding_details(self, scan_context, tmp_path):
        """Test that findings have all required details."""
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("""
FROM postgres:latest
USER root
        """)
        
        context = ScanContext(
            config=scan_context.config,
            target_path=str(tmp_path),
        )
        
        scanner = DockerScanner(context)
        findings = await scanner.scan(context)
        
        assert len(findings) > 0
        finding = findings[0]
        
        # Check all required fields
        assert finding.id is not None
        assert finding.title is not None
        assert finding.description is not None
        assert finding.severity is not None
        assert finding.category == FindingCategory.DOCKER
        assert finding.recommendation is not None
    
    @pytest.mark.asyncio
    async def test_scan_location_info(self, scan_context, tmp_path):
        """Test that findings include location information."""
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("""
FROM postgres:15
USER root
        """)
        
        context = ScanContext(
            config=scan_context.config,
            target_path=str(tmp_path),
        )
        
        scanner = DockerScanner(context)
        findings = await scanner.scan(context)
        
        assert len(findings) > 0
        # At least some findings should have location info
        located_findings = [f for f in findings if f.location is not None]
        assert len(located_findings) > 0
        
        if located_findings:
            loc = located_findings[0].location
            assert loc.file is not None
            assert "Dockerfile" in loc.file or "docker-compose" in loc.file
    
    @pytest.mark.asyncio
    async def test_recommendations_provided(self, scan_context, tmp_path):
        """Test that recommendations are provided."""
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("""
FROM postgres:latest
USER root
        """)
        
        context = ScanContext(
            config=scan_context.config,
            target_path=str(tmp_path),
        )
        
        scanner = DockerScanner(context)
        findings = await scanner.scan(context)
        
        assert len(findings) > 0
        for finding in findings:
            # Each finding should have a recommendation
            assert finding.recommendation is not None
            assert len(finding.recommendation) > 0

