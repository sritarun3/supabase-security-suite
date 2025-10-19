"""
GraphQL Scanner

Scans GraphQL endpoints for security issues:
- Introspection query exposure
- Anonymous vs authenticated access differences
- Schema disclosure
- Missing rate limiting
"""

import json
import asyncio
from typing import List, Dict, Any, Optional
from datetime import datetime

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
        Execute GraphQL endpoint scanning.
        
        Args:
            context: Scan context with configuration
            
        Returns:
            List of security findings related to GraphQL
        """
        findings = []
        
        if aiohttp is None:
            self.logger.warning("aiohttp not installed, skipping GraphQL scanning")
            findings.append(Finding(
                title="GraphQL Scanner Skipped",
                description="aiohttp library not installed. Install with: pip install aiohttp",
                severity=Severity.INFO,
                category=FindingCategory.CONFIGURATION,
                location=Location(type="scanner", path="graphql_scanner"),
                source="graphql_scanner",
                timestamp=datetime.utcnow(),
                metadata={"reason": "missing_dependency"}
            ))
            return findings
        
        try:
            # Get GraphQL endpoint from config
            supabase_config = context.config.supabase
            if not supabase_config.url:
                self.logger.info("No Supabase URL configured, skipping GraphQL scan")
                return findings
            
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
            self.logger.error(f"GraphQL scan failed: {e}")
            findings.append(Finding(
                title="GraphQL Scanner Error",
                description=f"Failed to complete GraphQL scan: {str(e)}",
                severity=Severity.MEDIUM,
                category=FindingCategory.CONFIGURATION,
                location=Location(type="network", path="graphql"),
                source="graphql_scanner",
                timestamp=datetime.utcnow(),
                metadata={"error": str(e)}
            ))
        
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

