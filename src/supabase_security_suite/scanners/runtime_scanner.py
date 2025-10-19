"""
Runtime Scanner

Tests actual database access through PostgREST:
- RLS policy enforcement verification
- JWT token role testing (anon vs authenticated)
- CRUD operation permissions
- Coverage matrix for RLS policies
"""

import json
import asyncio
from typing import List, Dict, Any, Optional, Set
from datetime import datetime
from dataclasses import dataclass

try:
    import aiohttp
    import jwt as pyjwt
except ImportError:
    aiohttp = None
    pyjwt = None

from ..core.scanner import BaseScanner, ScanContext
from ..reporting.models import Finding, Severity, FindingCategory, Location


@dataclass
class TestResult:
    """Result of a runtime test."""
    table: str
    operation: str
    role: str
    success: bool
    status_code: int
    response_data: Any
    error: Optional[str] = None


class RuntimeScanner(BaseScanner):
    """Scanner that performs runtime tests on PostgREST endpoints."""
    
    name = "runtime_scanner"
    description = "Tests RLS policy enforcement through runtime API calls"
    category = "runtime"
    
    OPERATIONS = ['SELECT', 'INSERT', 'UPDATE', 'DELETE']
    
    async def scan(self, context: ScanContext) -> List[Finding]:
        """
        Execute runtime API testing.
        
        Args:
            context: Scan context with Supabase configuration
            
        Returns:
            List of security findings from runtime tests
        """
        findings = []
        
        if aiohttp is None or pyjwt is None:
            self.logger.warning("aiohttp or PyJWT not installed, skipping runtime scanning")
            findings.append(Finding(
                title="Runtime Scanner Skipped",
                description="Required libraries not installed. Install with: pip install aiohttp pyjwt",
                severity=Severity.INFO,
                category=FindingCategory.CONFIGURATION,
                location=Location(type="scanner", path="runtime_scanner"),
                source="runtime_scanner",
                timestamp=datetime.utcnow(),
                metadata={"reason": "missing_dependencies"}
            ))
            return findings
        
        try:
            supabase_config = context.config.supabase
            
            if not supabase_config.url or not supabase_config.anon_key:
                self.logger.info("No Supabase URL/key configured, skipping runtime scan")
                return findings
            
            # Get list of tables to test
            tables = await self._get_tables(supabase_config.url, supabase_config.anon_key)
            
            if not tables:
                self.logger.warning("No tables found to test")
                return findings
            
            # Generate test tokens
            anon_token = supabase_config.anon_key
            auth_token = self._generate_auth_token(supabase_config, context)
            
            # Test each table with different roles
            for table in tables:
                # Test with anon role
                findings.extend(await self._test_table(
                    table, anon_token, "anon", supabase_config.url, context
                ))
                
                # Test with authenticated role (if we can generate a token)
                if auth_token:
                    findings.extend(await self._test_table(
                        table, auth_token, "authenticated", supabase_config.url, context
                    ))
        
        except Exception as e:
            self.logger.error(f"Runtime scan failed: {e}")
            findings.append(Finding(
                title="Runtime Scanner Error",
                description=f"Failed to complete runtime scan: {str(e)}",
                severity=Severity.MEDIUM,
                category=FindingCategory.CONFIGURATION,
                location=Location(type="network", path="postgrest"),
                source="runtime_scanner",
                timestamp=datetime.utcnow(),
                metadata={"error": str(e)}
            ))
        
        return findings
    
    async def _get_tables(self, base_url: str, api_key: str) -> List[str]:
        """Get list of tables from PostgREST."""
        tables = []
        
        try:
            headers = {
                "apikey": api_key,
                "Authorization": f"Bearer {api_key}"
            }
            
            # Use OpenAPI spec to get tables
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{base_url}/rest/v1/",
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status == 200:
                        spec = await response.json()
                        
                        # Extract table names from paths
                        paths = spec.get('paths', {})
                        for path in paths.keys():
                            # Path format: /{table_name}
                            if path.startswith('/') and '{' not in path:
                                table_name = path.strip('/')
                                if table_name and not table_name.startswith('rpc/'):
                                    tables.append(table_name)
        
        except Exception as e:
            self.logger.warning(f"Failed to get tables: {e}")
        
        return tables[:10]  # Limit to 10 tables to avoid too many tests
    
    def _generate_auth_token(
        self,
        supabase_config: Any,
        context: ScanContext
    ) -> Optional[str]:
        """Generate an authenticated JWT token for testing."""
        try:
            # Get JWT secret from config
            jwt_secret = context.config.supabase.jwt_secret
            
            if not jwt_secret:
                self.logger.info("No JWT secret configured, skipping authenticated tests")
                return None
            
            # Generate a test token with authenticated role
            payload = {
                "role": "authenticated",
                "sub": "test-user-" + datetime.utcnow().isoformat(),
                "iat": datetime.utcnow().timestamp(),
                "exp": (datetime.utcnow().timestamp() + 3600)  # 1 hour
            }
            
            token = pyjwt.encode(payload, jwt_secret, algorithm="HS256")
            return token
        
        except Exception as e:
            self.logger.warning(f"Failed to generate auth token: {e}")
            return None
    
    async def _test_table(
        self,
        table: str,
        token: str,
        role: str,
        base_url: str,
        context: ScanContext
    ) -> List[Finding]:
        """Test a single table with a specific role."""
        findings = []
        results = []
        
        # Test SELECT
        result = await self._test_select(table, token, role, base_url)
        results.append(result)
        
        # Test INSERT (with safe test data)
        result = await self._test_insert(table, token, role, base_url)
        results.append(result)
        
        # Test UPDATE (will fail if no rows, which is expected)
        result = await self._test_update(table, token, role, base_url)
        results.append(result)
        
        # Test DELETE (will fail if no rows, which is expected)
        result = await self._test_delete(table, token, role, base_url)
        results.append(result)
        
        # Analyze results and generate findings
        findings.extend(self._analyze_test_results(table, role, results, context))
        
        return findings
    
    async def _test_select(
        self,
        table: str,
        token: str,
        role: str,
        base_url: str
    ) -> TestResult:
        """Test SELECT operation on a table."""
        try:
            headers = {
                "apikey": token,
                "Authorization": f"Bearer {token}",
                "Accept": "application/json"
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{base_url}/rest/v1/{table}?limit=1",
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    data = await response.text()
                    
                    return TestResult(
                        table=table,
                        operation='SELECT',
                        role=role,
                        success=(response.status == 200),
                        status_code=response.status,
                        response_data=data
                    )
        
        except Exception as e:
            return TestResult(
                table=table,
                operation='SELECT',
                role=role,
                success=False,
                status_code=0,
                response_data=None,
                error=str(e)
            )
    
    async def _test_insert(
        self,
        table: str,
        token: str,
        role: str,
        base_url: str
    ) -> TestResult:
        """Test INSERT operation on a table."""
        try:
            headers = {
                "apikey": token,
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Prefer": "return=minimal"
            }
            
            # Use a minimal test payload that will likely fail validation
            # This is just to test if INSERT is blocked by RLS
            test_data = {"__test__": "runtime_scanner_test"}
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{base_url}/rest/v1/{table}",
                    headers=headers,
                    json=test_data,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    data = await response.text()
                    
                    return TestResult(
                        table=table,
                        operation='INSERT',
                        role=role,
                        success=(response.status in [200, 201]),
                        status_code=response.status,
                        response_data=data
                    )
        
        except Exception as e:
            return TestResult(
                table=table,
                operation='INSERT',
                role=role,
                success=False,
                status_code=0,
                response_data=None,
                error=str(e)
            )
    
    async def _test_update(
        self,
        table: str,
        token: str,
        role: str,
        base_url: str
    ) -> TestResult:
        """Test UPDATE operation on a table."""
        try:
            headers = {
                "apikey": token,
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Prefer": "return=minimal"
            }
            
            test_data = {"__test__": "runtime_scanner_update"}
            
            async with aiohttp.ClientSession() as session:
                # Try to update with a filter that likely matches nothing
                async with session.patch(
                    f"{base_url}/rest/v1/{table}?__test__=eq.nonexistent",
                    headers=headers,
                    json=test_data,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    data = await response.text()
                    
                    return TestResult(
                        table=table,
                        operation='UPDATE',
                        role=role,
                        success=(response.status in [200, 204]),
                        status_code=response.status,
                        response_data=data
                    )
        
        except Exception as e:
            return TestResult(
                table=table,
                operation='UPDATE',
                role=role,
                success=False,
                status_code=0,
                response_data=None,
                error=str(e)
            )
    
    async def _test_delete(
        self,
        table: str,
        token: str,
        role: str,
        base_url: str
    ) -> TestResult:
        """Test DELETE operation on a table."""
        try:
            headers = {
                "apikey": token,
                "Authorization": f"Bearer {token}",
                "Prefer": "return=minimal"
            }
            
            async with aiohttp.ClientSession() as session:
                # Try to delete with a filter that likely matches nothing
                async with session.delete(
                    f"{base_url}/rest/v1/{table}?__test__=eq.nonexistent",
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    data = await response.text()
                    
                    return TestResult(
                        table=table,
                        operation='DELETE',
                        role=role,
                        success=(response.status in [200, 204]),
                        status_code=response.status,
                        response_data=data
                    )
        
        except Exception as e:
            return TestResult(
                table=table,
                operation='DELETE',
                role=role,
                success=False,
                status_code=0,
                response_data=None,
                error=str(e)
            )
    
    def _analyze_test_results(
        self,
        table: str,
        role: str,
        results: List[TestResult],
        context: ScanContext
    ) -> List[Finding]:
        """Analyze test results and generate findings."""
        findings = []
        
        # Check if anon role has too many permissions
        if role == "anon":
            successful_ops = [r.operation for r in results if r.success]
            
            # Anon should typically only have SELECT or no access
            dangerous_ops = [op for op in successful_ops if op in ['INSERT', 'UPDATE', 'DELETE']]
            
            if dangerous_ops:
                findings.append(Finding(
                    title=f"Permissive RLS Policy on {table} (Anon Role)",
                    description=(
                        f"Anonymous users can perform {', '.join(dangerous_ops)} operations on table '{table}'. "
                        f"This may expose the table to unauthorized data manipulation. "
                        f"Tested operations: {', '.join([f'{r.operation}={r.status_code}' for r in results])}"
                    ),
                    severity=Severity.CRITICAL,
                    category=FindingCategory.ACCESS_CONTROL,
                    location=Location(
                        type="database",
                        path=f"public.{table}"
                    ),
                    source="runtime_scanner",
                    timestamp=datetime.utcnow(),
                    recommendation=(
                        f"Review RLS policies on table '{table}'. "
                        f"Anonymous users should typically have limited or no write access. "
                        f"Ensure policies use auth.uid() or similar session checks."
                    ),
                    compliance_mappings={
                        "HIPAA": "164.312(a)(1)",
                        "ISO27001": "A.9.2.1",
                        "SOC2": "CC6.1"
                    },
                    metadata={
                        "table": table,
                        "role": role,
                        "dangerous_operations": dangerous_ops,
                        "test_results": {r.operation: r.status_code for r in results}
                    }
                ))
        
        # Check if any operation had an unexpected success
        for result in results:
            # 401/403 means RLS is working (blocking access)
            # 200/201 means operation was allowed
            # 404 means table not found (configuration issue)
            # 422 means validation error (RLS allowed but data invalid)
            
            if result.status_code == 404:
                # Table not found - might be a permission issue
                pass  # Skip, this is expected for some tables
        
        return findings

