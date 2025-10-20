"""
Supabase CLI integration for enhanced security scanning.
"""

import json
import subprocess
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
import tempfile
import os


class SupabaseCLI:
    """Integration with Supabase CLI for project analysis."""
    
    def __init__(self, project_path: str):
        self.project_path = Path(project_path)
        self.cli_available = self._check_cli_availability()
        self.config_path = self.project_path / "supabase" / "config.toml"
    
    def _check_cli_availability(self) -> bool:
        """Check if Supabase CLI is available."""
        return shutil.which("supabase") is not None
    
    def get_project_info(self) -> Dict[str, Any]:
        """Get Supabase project information."""
        if not self.cli_available:
            return {"error": "Supabase CLI not available"}
        
        try:
            # Get project status
            result = subprocess.run(
                ["supabase", "status", "--output", "json"],
                cwd=self.project_path,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                return json.loads(result.stdout)
            else:
                return {"error": f"Failed to get project status: {result.stderr}"}
                
        except subprocess.TimeoutExpired:
            return {"error": "Timeout getting project status"}
        except Exception as e:
            return {"error": f"Error getting project info: {e}"}
    
    def get_migrations(self) -> List[Dict[str, Any]]:
        """Get list of database migrations."""
        if not self.cli_available:
            return []
        
        try:
            migrations_dir = self.project_path / "supabase" / "migrations"
            if not migrations_dir.exists():
                return []
            
            migrations = []
            for migration_file in sorted(migrations_dir.glob("*.sql")):
                migrations.append({
                    "filename": migration_file.name,
                    "path": str(migration_file),
                    "size": migration_file.stat().st_size,
                    "modified": migration_file.stat().st_mtime
                })
            
            return migrations
            
        except Exception as e:
            print(f"Error getting migrations: {e}")
            return []
    
    def get_functions(self) -> List[Dict[str, Any]]:
        """Get list of Edge Functions."""
        if not self.cli_available:
            return []
        
        try:
            functions_dir = self.project_path / "supabase" / "functions"
            if not functions_dir.exists():
                return []
            
            functions = []
            for function_dir in functions_dir.iterdir():
                if function_dir.is_dir():
                    index_file = function_dir / "index.ts"
                    if index_file.exists():
                        functions.append({
                            "name": function_dir.name,
                            "path": str(function_dir),
                            "index_file": str(index_file),
                            "size": index_file.stat().st_size,
                            "modified": index_file.stat().st_mtime
                        })
            
            return functions
            
        except Exception as e:
            print(f"Error getting functions: {e}")
            return []
    
    def get_policies(self) -> List[Dict[str, Any]]:
        """Extract RLS policies from migrations."""
        policies = []
        migrations = self.get_migrations()
        
        for migration in migrations:
            try:
                with open(migration["path"], 'r') as f:
                    content = f.read()
                
                # Extract policy definitions
                policy_matches = self._extract_policies_from_sql(content)
                for policy in policy_matches:
                    policy["migration_file"] = migration["filename"]
                    policies.append(policy)
                    
            except Exception as e:
                print(f"Error reading migration {migration['filename']}: {e}")
        
        return policies
    
    def _extract_policies_from_sql(self, sql_content: str) -> List[Dict[str, Any]]:
        """Extract RLS policy information from SQL content."""
        import re
        
        policies = []
        
        # Pattern to match CREATE POLICY statements
        policy_pattern = r"CREATE\s+POLICY\s+(\w+)\s+ON\s+(\w+\.?\w*)\s+FOR\s+(\w+)\s+(?:USING\s*\(([^)]+)\))?\s*(?:WITH\s+CHECK\s*\(([^)]+)\))?"
        
        matches = re.finditer(policy_pattern, sql_content, re.IGNORECASE | re.MULTILINE)
        
        for match in matches:
            policy_name = match.group(1)
            table_name = match.group(2)
            operation = match.group(3)
            using_clause = match.group(4) or ""
            with_check_clause = match.group(5) or ""
            
            policies.append({
                "name": policy_name,
                "table": table_name,
                "operation": operation,
                "using_clause": using_clause,
                "with_check_clause": with_check_clause,
                "is_permissive": "true" in using_clause.lower() if using_clause else False
            })
        
        return policies
    
    def get_tables_with_rls(self) -> List[Dict[str, Any]]:
        """Get tables and their RLS status."""
        tables = []
        migrations = self.get_migrations()
        
        for migration in migrations:
            try:
                with open(migration["path"], 'r') as f:
                    content = f.read()
                
                # Extract table definitions and RLS settings
                table_matches = self._extract_tables_from_sql(content)
                for table in table_matches:
                    table["migration_file"] = migration["filename"]
                    tables.append(table)
                    
            except Exception as e:
                print(f"Error reading migration {migration['filename']}: {e}")
        
        return tables
    
    def _extract_tables_from_sql(self, sql_content: str) -> List[Dict[str, Any]]:
        """Extract table information from SQL content."""
        import re
        
        tables = []
        
        # Pattern to match CREATE TABLE statements
        table_pattern = r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+\.?\w*)\s*\("
        
        # Pattern to match ALTER TABLE ENABLE/DISABLE RLS
        rls_pattern = r"ALTER\s+TABLE\s+(\w+\.?\w*)\s+(ENABLE|DISABLE)\s+ROW\s+LEVEL\s+SECURITY"
        
        table_matches = re.finditer(table_pattern, sql_content, re.IGNORECASE | re.MULTILINE)
        rls_matches = re.finditer(rls_pattern, sql_content, re.IGNORECASE | re.MULTILINE)
        
        # Create a map of RLS settings
        rls_settings = {}
        for match in rls_matches:
            table_name = match.group(1)
            rls_status = match.group(2).lower() == "enable"
            rls_settings[table_name] = rls_status
        
        for match in table_matches:
            table_name = match.group(1)
            tables.append({
                "name": table_name,
                "rls_enabled": rls_settings.get(table_name, False),
                "has_policies": False  # Will be updated by policy analysis
            })
        
        return tables
    
    def validate_project_structure(self) -> Dict[str, Any]:
        """Validate Supabase project structure."""
        validation = {
            "valid": True,
            "issues": [],
            "warnings": [],
            "structure": {}
        }
        
        # Check for required directories
        required_dirs = [
            "supabase",
            "supabase/migrations",
            "supabase/functions"
        ]
        
        for dir_path in required_dirs:
            full_path = self.project_path / dir_path
            validation["structure"][dir_path] = {
                "exists": full_path.exists(),
                "path": str(full_path)
            }
            
            if not full_path.exists():
                validation["issues"].append(f"Missing required directory: {dir_path}")
                validation["valid"] = False
        
        # Check for config.toml
        config_exists = self.config_path.exists()
        validation["structure"]["config.toml"] = {
            "exists": config_exists,
            "path": str(self.config_path)
        }
        
        if not config_exists:
            validation["warnings"].append("No config.toml found - using defaults")
        
        # Check for migrations
        migrations = self.get_migrations()
        validation["structure"]["migrations"] = {
            "count": len(migrations),
            "files": [m["filename"] for m in migrations]
        }
        
        if len(migrations) == 0:
            validation["warnings"].append("No database migrations found")
        
        # Check for functions
        functions = self.get_functions()
        validation["structure"]["functions"] = {
            "count": len(functions),
            "names": [f["name"] for f in functions]
        }
        
        return validation
    
    def get_security_recommendations(self) -> List[Dict[str, Any]]:
        """Get Supabase-specific security recommendations."""
        recommendations = []
        
        # Check project structure
        validation = self.validate_project_structure()
        if not validation["valid"]:
            recommendations.append({
                "type": "structure",
                "severity": "HIGH",
                "title": "Invalid Supabase project structure",
                "description": "Project is missing required Supabase directories",
                "recommendation": "Run 'supabase init' to initialize project structure"
            })
        
        # Check for RLS policies
        policies = self.get_policies()
        tables = self.get_tables_with_rls()
        
        tables_without_policies = []
        for table in tables:
            if table["rls_enabled"]:
                has_policy = any(p["table"] == table["name"] for p in policies)
                if not has_policy:
                    tables_without_policies.append(table["name"])
        
        if tables_without_policies:
            recommendations.append({
                "type": "rls",
                "severity": "HIGH",
                "title": "Tables with RLS enabled but no policies",
                "description": f"Tables {', '.join(tables_without_policies)} have RLS enabled but no policies defined",
                "recommendation": "Add appropriate RLS policies or disable RLS if not needed"
            })
        
        # Check for permissive policies
        permissive_policies = [p for p in policies if p["is_permissive"]]
        if permissive_policies:
            recommendations.append({
                "type": "rls",
                "severity": "MEDIUM",
                "title": "Permissive RLS policies detected",
                "description": f"Found {len(permissive_policies)} policies with 'true' conditions",
                "recommendation": "Review and restrict permissive policies for better security"
            })
        
        return recommendations
