"""
Database security scanner for PostgreSQL/Supabase databases.
"""

import re
from typing import Dict, List, Optional, Any
import psycopg
from psycopg import sql

from ..core.finding import SecurityFinding, FindingSeverity, FindingSource, get_compliance_mapping
from ..core.config import SecurityConfig


class DatabaseScanner:
    """Database security scanner for live PostgreSQL connections."""
    
    def __init__(self, config: SecurityConfig):
        self.config = config
        self.connection = None
    
    def scan_database(self) -> List[SecurityFinding]:
        """Perform comprehensive database security scan."""
        findings = []
        
        if not self.config.supabase_config.database_url:
            return findings
        
        try:
            # Connect to database
            with psycopg.connect(
                self.config.supabase_config.database_url,
                connect_timeout=self.config.scan_settings.timeout_seconds
            ) as conn:
                self.connection = conn
                
                # Run various security checks
                findings.extend(self._check_rls_status())
                findings.extend(self._check_security_definer_functions())
                findings.extend(self._check_search_path())
                findings.extend(self._check_privileges())
                findings.extend(self._check_extensions())
                findings.extend(self._check_weak_passwords())
                
        except Exception as e:
            findings.append(SecurityFinding(
                id="db:connection_error",
                title="Database connection failed",
                severity=FindingSeverity.MEDIUM,
                confidence="HIGH",
                description=f"Could not connect to database: {e}",
                impact="Unable to perform database security checks",
                recommendation="Check database URL and connection parameters",
                source=FindingSource.DATABASE,
                metadata={"error": str(e)}
            ))
        
        return findings
    
    def _check_rls_status(self) -> List[SecurityFinding]:
        """Check Row Level Security status on tables."""
        findings = []
        
        try:
            with self.connection.cursor() as cur:
                # Get tables without RLS enabled
                cur.execute("""
                    SELECT n.nspname, c.relname
                    FROM pg_class c
                    JOIN pg_namespace n ON n.oid = c.relnamespace
                    WHERE c.relkind = 'r'
                      AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
                      AND NOT c.relrowsecurity
                    ORDER BY n.nspname, c.relname
                """)
                
                tables_without_rls = cur.fetchall()
                
                for schema, table in tables_without_rls:
                    findings.append(SecurityFinding(
                        id=f"db:rls_disabled:{schema}.{table}",
                        title=f"RLS disabled on {schema}.{table}",
                        severity=FindingSeverity.HIGH,
                        confidence="HIGH",
                        description=f"Table {schema}.{table} does not have Row Level Security enabled",
                        impact="Data in this table is not protected by RLS policies",
                        recommendation="Enable RLS and create appropriate policies",
                        source=FindingSource.DATABASE,
                        metadata={"schema": schema, "table": table}
                    ))
                
                # Get tables with RLS but no policies
                cur.execute("""
                    SELECT n.nspname, c.relname
                    FROM pg_class c
                    JOIN pg_namespace n ON n.oid = c.relnamespace
                    WHERE c.relkind = 'r'
                      AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
                      AND c.relrowsecurity
                      AND NOT EXISTS (
                          SELECT 1 FROM pg_policy p 
                          WHERE p.polrelid = c.oid
                      )
                    ORDER BY n.nspname, c.relname
                """)
                
                tables_without_policies = cur.fetchall()
                
                for schema, table in tables_without_policies:
                    findings.append(SecurityFinding(
                        id=f"db:rls_no_policies:{schema}.{table}",
                        title=f"RLS enabled but no policies on {schema}.{table}",
                        severity=FindingSeverity.HIGH,
                        confidence="HIGH",
                        description=f"Table {schema}.{table} has RLS enabled but no policies defined",
                        impact="RLS is enabled but provides no protection without policies",
                        recommendation="Create appropriate RLS policies for this table",
                        source=FindingSource.DATABASE,
                        metadata={"schema": schema, "table": table}
                    ))
        
        except Exception as e:
            findings.append(SecurityFinding(
                id="db:rls_check_error",
                title="RLS status check failed",
                severity=FindingSeverity.MEDIUM,
                confidence="LOW",
                description=f"Error checking RLS status: {e}",
                impact="Unable to verify RLS configuration",
                recommendation="Check database permissions and RLS configuration",
                source=FindingSource.DATABASE,
                metadata={"error": str(e)}
            ))
        
        return findings
    
    def _check_security_definer_functions(self) -> List[SecurityFinding]:
        """Check for SECURITY DEFINER functions without proper search_path."""
        findings = []
        
        try:
            with self.connection.cursor() as cur:
                cur.execute("""
                    SELECT n.nspname, p.proname, pg_get_functiondef(p.oid) as definition
                    FROM pg_proc p
                    JOIN pg_namespace n ON n.oid = p.pronamespace
                    WHERE p.prosecdef = true
                      AND n.nspname NOT IN ('pg_catalog', 'information_schema')
                """)
                
                security_definer_functions = cur.fetchall()
                
                for schema, func_name, definition in security_definer_functions:
                    # Check if function has search_path set
                    if not re.search(r"(?i)SET\s+search_path\s*=", definition or ""):
                        findings.append(SecurityFinding(
                            id=f"db:sec_def_no_searchpath:{schema}.{func_name}",
                            title=f"SECURITY DEFINER function without search_path: {schema}.{func_name}",
                            severity=FindingSeverity.CRITICAL,
                            confidence="HIGH",
                            description=f"Function {schema}.{func_name} runs with elevated privileges without fixed search_path",
                            impact="Privilege escalation possible via schema hijacking",
                            recommendation="Add 'SET search_path = pg_catalog, public;' to function definition",
                            source=FindingSource.DATABASE,
                            metadata={"schema": schema, "function": func_name}
                        ))
        
        except Exception as e:
            findings.append(SecurityFinding(
                id="db:sec_def_check_error",
                title="SECURITY DEFINER check failed",
                severity=FindingSeverity.MEDIUM,
                confidence="LOW",
                description=f"Error checking SECURITY DEFINER functions: {e}",
                impact="Unable to verify function security",
                recommendation="Check database permissions and function definitions",
                source=FindingSource.DATABASE,
                metadata={"error": str(e)}
            ))
        
        return findings
    
    def _check_search_path(self) -> List[SecurityFinding]:
        """Check global search_path configuration."""
        findings = []
        
        try:
            with self.connection.cursor() as cur:
                cur.execute("SHOW search_path")
                search_path = cur.fetchone()[0]
                
                # Check for unsafe search_path patterns
                if re.search(r"\$user|public,", search_path or ""):
                    findings.append(SecurityFinding(
                        id="db:unsafe_search_path",
                        title=f"Unsafe search_path configuration: {search_path}",
                        severity=FindingSeverity.MEDIUM,
                        confidence="MEDIUM",
                        description="Default search_path includes user-writable schemas",
                        impact="Schema hijacking possible if untrusted users can create objects",
                        recommendation="Set search_path to 'pg_catalog, public' or more restrictive",
                        source=FindingSource.DATABASE,
                        metadata={"search_path": search_path}
                    ))
        
        except Exception as e:
            findings.append(SecurityFinding(
                id="db:search_path_check_error",
                title="Search path check failed",
                severity=FindingSeverity.MEDIUM,
                confidence="LOW",
                description=f"Error checking search_path: {e}",
                impact="Unable to verify search_path security",
                recommendation="Check database permissions and configuration",
                source=FindingSource.DATABASE,
                metadata={"error": str(e)}
            ))
        
        return findings
    
    def _check_privileges(self) -> List[SecurityFinding]:
        """Check for dangerous privilege grants."""
        findings = []
        
        try:
            with self.connection.cursor() as cur:
                # Check for grants to public role
                cur.execute("""
                    SELECT grantee, privilege_type, table_name, table_schema
                    FROM information_schema.table_privileges
                    WHERE grantee = 'public'
                      AND table_schema NOT IN ('information_schema', 'pg_catalog')
                """)
                
                public_grants = cur.fetchall()
                
                for grantee, privilege, table, schema in public_grants:
                    findings.append(SecurityFinding(
                        id=f"db:public_grant:{schema}.{table}:{privilege}",
                        title=f"Dangerous grant to public role: {privilege} on {schema}.{table}",
                        severity=FindingSeverity.HIGH,
                        confidence="HIGH",
                        description=f"Public role has {privilege} privilege on {schema}.{table}",
                        impact="Public access to sensitive operations",
                        recommendation="Remove public grants and use specific roles",
                        source=FindingSource.DATABASE,
                        metadata={"schema": schema, "table": table, "privilege": privilege}
                    ))
                
                # Check for superuser ownership
                cur.execute("""
                    SELECT n.nspname, c.relname, c.relowner, r.rolname
                    FROM pg_class c
                    JOIN pg_namespace n ON n.oid = c.relnamespace
                    JOIN pg_roles r ON r.oid = c.relowner
                    WHERE c.relkind = 'r'
                      AND n.nspname NOT IN ('pg_catalog', 'information_schema')
                      AND r.rolsuper = true
                """)
                
                superuser_owned = cur.fetchall()
                
                for schema, table, owner_oid, owner_name in superuser_owned:
                    findings.append(SecurityFinding(
                        id=f"db:superuser_owned:{schema}.{table}",
                        title=f"Table owned by superuser: {schema}.{table}",
                        severity=FindingSeverity.MEDIUM,
                        confidence="HIGH",
                        description=f"Table {schema}.{table} is owned by superuser {owner_name}",
                        impact="Superuser ownership increases attack surface",
                        recommendation="Transfer ownership to specific application roles",
                        source=FindingSource.DATABASE,
                        metadata={"schema": schema, "table": table, "owner": owner_name}
                    ))
        
        except Exception as e:
            findings.append(SecurityFinding(
                id="db:privilege_check_error",
                title="Privilege check failed",
                severity=FindingSeverity.MEDIUM,
                confidence="LOW",
                description=f"Error checking privileges: {e}",
                impact="Unable to verify privilege configuration",
                recommendation="Check database permissions and privilege grants",
                source=FindingSource.DATABASE,
                metadata={"error": str(e)}
            ))
        
        return findings
    
    def _check_extensions(self) -> List[SecurityFinding]:
        """Check for potentially dangerous extensions."""
        findings = []
        
        dangerous_extensions = {
            'plpythonu': 'PL/PythonU allows arbitrary code execution',
            'plpython2u': 'PL/Python2U allows arbitrary code execution',
            'plpython3u': 'PL/Python3U allows arbitrary code execution',
            'plperlu': 'PL/PerlU allows arbitrary code execution',
            'pltclu': 'PL/TclU allows arbitrary code execution'
        }
        
        try:
            with self.connection.cursor() as cur:
                cur.execute("""
                    SELECT extname, extversion
                    FROM pg_extension
                    WHERE extname IN %s
                """, (tuple(dangerous_extensions.keys()),))
                
                installed_dangerous = cur.fetchall()
                
                for ext_name, ext_version in installed_dangerous:
                    findings.append(SecurityFinding(
                        id=f"db:dangerous_extension:{ext_name}",
                        title=f"Dangerous extension installed: {ext_name}",
                        severity=FindingSeverity.HIGH,
                        confidence="HIGH",
                        description=f"Extension {ext_name} v{ext_version} is installed",
                        impact=dangerous_extensions[ext_name],
                        recommendation="Remove or restrict access to this extension",
                        source=FindingSource.DATABASE,
                        metadata={"extension": ext_name, "version": ext_version}
                    ))
        
        except Exception as e:
            findings.append(SecurityFinding(
                id="db:extension_check_error",
                title="Extension check failed",
                severity=FindingSeverity.MEDIUM,
                confidence="LOW",
                description=f"Error checking extensions: {e}",
                impact="Unable to verify extension security",
                recommendation="Check database permissions and extension configuration",
                source=FindingSource.DATABASE,
                metadata={"error": str(e)}
            ))
        
        return findings
    
    def _check_weak_passwords(self) -> List[SecurityFinding]:
        """Check for weak passwords in user accounts."""
        findings = []
        
        try:
            with self.connection.cursor() as cur:
                # This is a simplified check - in practice, you'd need more sophisticated password analysis
                cur.execute("""
                    SELECT rolname, rolpassword
                    FROM pg_authid
                    WHERE rolpassword IS NOT NULL
                      AND rolname NOT IN ('postgres', 'supabase_admin')
                """)
                
                user_passwords = cur.fetchall()
                
                for username, password_hash in user_passwords:
                    # Check for weak password patterns (simplified)
                    if password_hash and len(password_hash) < 20:
                        findings.append(SecurityFinding(
                            id=f"db:weak_password:{username}",
                            title=f"Potentially weak password for user: {username}",
                            severity=FindingSeverity.MEDIUM,
                            confidence="LOW",
                            description=f"Password hash for user {username} appears weak",
                            impact="Weak passwords are easily compromised",
                            recommendation="Enforce strong password policies",
                            source=FindingSource.DATABASE,
                            metadata={"username": username}
                        ))
        
        except Exception as e:
            findings.append(SecurityFinding(
                id="db:password_check_error",
                title="Password check failed",
                severity=FindingSeverity.MEDIUM,
                confidence="LOW",
                description=f"Error checking passwords: {e}",
                impact="Unable to verify password strength",
                recommendation="Check database permissions and password policies",
                source=FindingSource.DATABASE,
                metadata={"error": str(e)}
            ))
        
        return findings
