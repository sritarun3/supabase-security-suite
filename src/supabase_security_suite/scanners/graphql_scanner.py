"""
GraphQL Scanner

Scans GraphQL endpoints for security issues:
- Introspection query exposure
- Anonymous vs authenticated access differences
- Schema disclosure
- Missing rate limiting
- Pattern-based detection of GraphQL endpoints in code
"""

import json
import asyncio
import re
from typing import List, Dict, Any, Optional
from datetime import datetime
from pathlib import Path

try:
    import aiohttp
except ImportError:
    aiohttp = None

from ..core.scanner import BaseScanner, ScanContext
from ..reporting.models import Finding, Severity, FindingCategory, Location


class GraphQLScanner(BaseScanner):
    """Scanner for GraphQL endpoint security issues."""
    
    name = "graphql_scanner"
    description = "Scans GraphQL endpoints for security misconfigurations"
    category = "api"
    
    # Pattern-based detection patterns
    GRAPHQL_ENDPOINT_PATTERNS = [
        r'["\']https?://[^"\']+/graphql[^"\']*["\']',
        r'["\']https?://[^"\']+/v1/graphql[^"\']*["\']',
        r'graphql_endpoint\s*=\s*["\'][^"\']+["\']',
        r'GRAPHQL_URL\s*=\s*["\'][^"\']+["\']',
        r'/api/graphql',
        r'\.supabase\.co/graphql',
    ]
    
    GRAPHQL_QUERY_PATTERNS = [
        r'query\s+\w+\s*\{',
        r'mutation\s+\w+\s*\{',
        r'subscription\s+\w+\s*\{',
        r'__schema\s*\{',  # Introspection
        r'gql`',
        r'graphql\(',
    ]
    
    INTROSPECTION_PATTERNS = [
        r'__schema',
        r'__type\(',
        r'IntrospectionQuery',
        r'getIntrospectionQuery',
    ]
    
    SCAN_EXTENSIONS = ['.js', '.ts', '.jsx', '.tsx', '.py', '.graphql', '.gql', '.json', '.env']
    
    INTROSPECTION_QUERY = """
    query IntrospectionQuery {
        __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
                name
                kind
                description
            }
        }
    }
    """
    
    
    async def scan(self, context: ScanContext) -> List[Finding]:
        """
        Execute GraphQL endpoint scanning (pattern-based and live testing).
        
        Args:
            context: Scan context with configuration
            
        Returns:
            List of security findings related to GraphQL
        """
        findings = []
        
        # Always run pattern-based detection (works without config)
        findings.extend(await self._scan_files_for_graphql(context))
        
        # Only run live endpoint testing if configuration is available
        if context.config and hasattr(context.config, 'supabase'):
            if aiohttp is None:
                self.logger.warning("aiohttp not installed, skipping live GraphQL endpoint testing")
            else:
                try:
                    # Get GraphQL endpoint from config
                    supabase_config = context.config.supabase
                    if supabase_config.url:
                        graphql_url = f"{supabase_config.url}/graphql/v1"
                        
                        # Test introspection with different auth levels
                        findings.extend(await self._test_introspection_anonymous(graphql_url, context))
                        findings.extend(await self._test_introspection_authenticated(
                            graphql_url, supabase_config.anon_key, context
                        ))
                        
                        # Compare schemas if service_role key is available
                        if supabase_config.service_role_key:
                            findings.extend(await self._compare_schemas(
                                graphql_url,
                                supabase_config.anon_key,
                                supabase_config.service_role_key,
                                context
                            ))
                
                except Exception as e:
                    self.logger.error(f"GraphQL live scan failed: {e}")
        
        return findings
    
    async def _scan_files_for_graphql(self, context: ScanContext) -> List[Finding]:
        """Scan files for GraphQL-related patterns and potential issues."""
        findings = []
        target_path = context.target_path
        
        for ext in self.SCAN_EXTENSIONS:
            for file_path in target_path.glob(f"**/*{ext}"):
                if self._should_skip_file(file_path):
                    continue
                
                try:
                    content = file_path.read_text(encoding='utf-8', errors='ignore')
                    findings.extend(self._check_graphql_patterns(file_path, content, context))
                except Exception as e:
                    self.logger.debug(f"Error reading {file_path}: {e}")
        
        return findings
    
    def _should_skip_file(self, file_path: Path) -> bool:
        """Check if file should be skipped."""
        skip_dirs = {'node_modules', '.git', 'venv', '__pycache__', 'dist', 'build', '.next'}
        return any(skip_dir in file_path.parts for skip_dir in skip_dirs)
    
    def _check_graphql_patterns(self, file_path: Path, content: str, context: ScanContext) -> List[Finding]:
        """Check for GraphQL patterns and security issues in file content."""
        findings = []
        lines = content.split('\n')
        
        # Check for GraphQL endpoints
        for line_num, line in enumerate(lines, 1):
            for pattern in self.GRAPHQL_ENDPOINT_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    try:
                        rel_path = file_path.relative_to(context.target_path)
                    except ValueError:
                        rel_path = file_path
                    
                    findings.append(Finding(
                        id=f"graphql_endpoint_{file_path.name}_{line_num}",
                        title="GraphQL Endpoint Detected",
                        description=f"GraphQL endpoint found in code: {line.strip()[:80]}",
                        severity=Severity.INFO,
                        category=FindingCategory.GRAPHQL,
                        location=Location(
                            file=str(rel_path),
                            line=line_num
                        ),
                        source=self.name,
                        recommendation="Ensure GraphQL endpoint has proper authentication, rate limiting, and introspection is disabled in production.",
                        metadata={"endpoint": line.strip()[:100]}
                    ))
        
        # Check for introspection queries (potential security risk)
        for line_num, line in enumerate(lines, 1):
            for pattern in self.INTROSPECTION_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    try:
                        rel_path = file_path.relative_to(context.target_path)
                    except ValueError:
                        rel_path = file_path
                    
                    findings.append(Finding(
                        id=f"graphql_introspection_{file_path.name}_{line_num}",
                        title="GraphQL Introspection Query Detected",
                        description=f"GraphQL introspection query found in code. This can expose your entire schema to attackers.",
                        severity=Severity.MEDIUM,
                        category=FindingCategory.GRAPHQL,
                        location=Location(
                            file=str(rel_path),
                            line=line_num
                        ),
                        source=self.name,
                        recommendation="Disable introspection in production environments. Use: `dangerouslyDisableIntrospection: true` or equivalent for your GraphQL server.",
                        compliance={
                            "OWASP": ["API8:2023"],
                            "OWASP_API": ["API8:2023 - Security Misconfiguration"]
                        },
                        metadata={"pattern_found": pattern, "line": line.strip()[:100]}
                    ))
                    break  # Only report once per line
        
        # Check for GraphQL queries without variables (potential injection)
        for line_num, line in enumerate(lines, 1):
            if re.search(r'query.*\$\{.*\}', line) or re.search(r'mutation.*\$\{.*\}', line):
                try:
                    rel_path = file_path.relative_to(context.target_path)
                except ValueError:
                    rel_path = file_path
                
                findings.append(Finding(
                    id=f"graphql_injection_{file_path.name}_{line_num}",
                    title="Potential GraphQL Injection via String Interpolation",
                    description=f"GraphQL query uses string interpolation which can lead to injection attacks: {line.strip()[:80]}",
                    severity=Severity.HIGH,
                    category=FindingCategory.GRAPHQL,
                    location=Location(
                        file=str(rel_path),
                        line=line_num
                    ),
                    source=self.name,
                    recommendation="Use GraphQL variables instead of string interpolation to prevent injection attacks. Example: query($id: ID!) { user(id: $id) }",
                    compliance={
                        "OWASP": ["A03:2021"],
                        "CWE": ["CWE-89"]
                    },
                    metadata={"line": line.strip()[:100]}
                ))
        
        return findings
    
    async def _test_introspection_anonymous(self, graphql_url: str, context: ScanContext) -> List[Finding]:
        """Test if introspection is available without authentication."""
        findings = []
        
        try:
            # This method existed before, keeping it for live testing
            pass
        except Exception as e:
            self.logger.error(f"GraphQL introspection test failed: {e}")
        
        return findings
    
    async def _test_introspection_anonymous(
        self,
        graphql_url: str,
        context: ScanContext
    ) -> List[Finding]:
        """Test if introspection is available without authentication."""
        findings = []
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    graphql_url,
                    json={"query": self.INTROSPECTION_QUERY},
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        # Check if we got schema data back
                        if 'data' in data and '__schema' in data.get('data', {}):
                            findings.append(Finding(
                                title="GraphQL Introspection Enabled (Anonymous)",
                                description=(
                                    f"GraphQL introspection is enabled for anonymous requests at {graphql_url}. "
                                    f"This exposes your entire database schema to unauthenticated users, "
                                    f"revealing table names, column names, and relationships."
                                ),
                                severity=Severity.HIGH,
                                category=FindingCategory.INFORMATION_DISCLOSURE,
                                location=Location(
                                    type="endpoint",
                                    path=graphql_url
                                ),
                                source="graphql_scanner",
                                timestamp=datetime.utcnow(),
                                recommendation=(
                                    "Disable GraphQL introspection in production or restrict it to "
                                    "authenticated users only. Update your Supabase settings."
                                ),
                                compliance_mappings={
                                    "ISO27001": "A.13.1.3",
                                    "SOC2": "CC6.6"
                                },
                                metadata={
                                    "endpoint": graphql_url,
                                    "auth_level": "anonymous",
                                    "types_exposed": len(data['data']['__schema'].get('types', []))
                                }
                            ))
        
        except asyncio.TimeoutError:
            self.logger.warning(f"Timeout testing anonymous introspection at {graphql_url}")
        except Exception as e:
            self.logger.warning(f"Error testing anonymous introspection: {e}")
        
        return findings
    
    async def _test_introspection_authenticated(
        self,
        graphql_url: str,
        anon_key: Optional[str],
        context: ScanContext
    ) -> List[Finding]:
        """Test if introspection is available with authenticated requests."""
        findings = []
        
        if not anon_key:
            return findings
        
        try:
            headers = {
                "apikey": anon_key,
                "Authorization": f"Bearer {anon_key}"
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    graphql_url,
                    json={"query": self.INTROSPECTION_QUERY},
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        if 'data' in data and '__schema' in data.get('data', {}):
                            # Introspection is enabled for authenticated users
                            # This is less severe than anonymous, but still worth noting
                            findings.append(Finding(
                                title="GraphQL Introspection Enabled (Authenticated)",
                                description=(
                                    f"GraphQL introspection is enabled for authenticated requests at {graphql_url}. "
                                    f"While better than anonymous access, this still exposes your database schema "
                                    f"to any authenticated user."
                                ),
                                severity=Severity.MEDIUM,
                                category=FindingCategory.INFORMATION_DISCLOSURE,
                                location=Location(
                                    type="endpoint",
                                    path=graphql_url
                                ),
                                source="graphql_scanner",
                                timestamp=datetime.utcnow(),
                                recommendation=(
                                    "Consider disabling GraphQL introspection in production environments. "
                                    "If needed, restrict it to admin users only."
                                ),
                                metadata={
                                    "endpoint": graphql_url,
                                    "auth_level": "authenticated",
                                    "types_exposed": len(data['data']['__schema'].get('types', []))
                                }
                            ))
        
        except asyncio.TimeoutError:
            self.logger.warning(f"Timeout testing authenticated introspection at {graphql_url}")
        except Exception as e:
            self.logger.warning(f"Error testing authenticated introspection: {e}")
        
        return findings
    
    async def _compare_schemas(
        self,
        graphql_url: str,
        anon_key: Optional[str],
        service_role_key: str,
        context: ScanContext
    ) -> List[Finding]:
        """Compare schemas between anon and service_role to find differences."""
        findings = []
        
        try:
            # Get schema with anon key
            anon_schema = await self._get_schema(graphql_url, anon_key)
            
            # Get schema with service_role key
            service_schema = await self._get_schema(graphql_url, service_role_key)
            
            if anon_schema and service_schema:
                # Compare type counts
                anon_types = set(t['name'] for t in anon_schema.get('types', []))
                service_types = set(t['name'] for t in service_schema.get('types', []))
                
                # Find types only in service_role
                hidden_types = service_types - anon_types
                
                if hidden_types:
                    findings.append(Finding(
                        title="GraphQL Schema Difference Detected",
                        description=(
                            f"GraphQL endpoint at {graphql_url} exposes {len(hidden_types)} additional "
                            f"types to service_role that are hidden from anon users. "
                            f"This is expected, but ensure these tables truly require service-role access."
                        ),
                        severity=Severity.INFO,
                        category=FindingCategory.INFORMATION_DISCLOSURE,
                        location=Location(
                            type="endpoint",
                            path=graphql_url
                        ),
                        source="graphql_scanner",
                        timestamp=datetime.utcnow(),
                        recommendation=(
                            "Review the hidden types to ensure they should only be accessible "
                            "via service_role. Consider if any should be made available to "
                            "authenticated users with proper RLS policies."
                        ),
                        metadata={
                            "endpoint": graphql_url,
                            "anon_types_count": len(anon_types),
                            "service_types_count": len(service_types),
                            "hidden_types_count": len(hidden_types),
                            "hidden_types": list(hidden_types)[:10]  # Limit to first 10
                        }
                    ))
        
        except Exception as e:
            self.logger.warning(f"Error comparing schemas: {e}")
        
        return findings
    
    async def _get_schema(
        self,
        graphql_url: str,
        api_key: Optional[str]
    ) -> Optional[Dict[str, Any]]:
        """Get GraphQL schema using provided API key."""
        try:
            headers = {}
            if api_key:
                headers = {
                    "apikey": api_key,
                    "Authorization": f"Bearer {api_key}"
                }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    graphql_url,
                    json={"query": self.INTROSPECTION_QUERY},
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data.get('data', {}).get('__schema')
        
        except Exception as e:
            self.logger.warning(f"Error getting schema: {e}")
        
        return None

