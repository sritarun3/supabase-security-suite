"""
Supabase configuration parser for config.toml files.
"""

import toml
from pathlib import Path
from typing import Dict, List, Optional, Any


class SupabaseConfigParser:
    """Parser for Supabase config.toml files."""
    
    def __init__(self, config_path: str):
        self.config_path = Path(config_path)
        self.config_data = {}
        self._load_config()
    
    def _load_config(self) -> None:
        """Load configuration from TOML file."""
        if not self.config_path.exists():
            raise FileNotFoundError(f"Config file not found: {self.config_path}")
        
        try:
            with open(self.config_path, 'r') as f:
                self.config_data = toml.load(f)
        except Exception as e:
            raise ValueError(f"Error parsing config file: {e}")
    
    def get_project_id(self) -> Optional[str]:
        """Get the project ID from config."""
        return self.config_data.get("project_id")
    
    def get_database_config(self) -> Dict[str, Any]:
        """Get database configuration."""
        return self.config_data.get("db", {})
    
    def get_auth_config(self) -> Dict[str, Any]:
        """Get authentication configuration."""
        return self.config_data.get("auth", {})
    
    def get_api_config(self) -> Dict[str, Any]:
        """Get API configuration."""
        return self.config_data.get("api", {})
    
    def get_storage_config(self) -> Dict[str, Any]:
        """Get storage configuration."""
        return self.config_data.get("storage", {})
    
    def get_realtime_config(self) -> Dict[str, Any]:
        """Get realtime configuration."""
        return self.config_data.get("realtime", {})
    
    def get_edge_functions_config(self) -> Dict[str, Any]:
        """Get Edge Functions configuration."""
        return self.config_data.get("functions", {})
    
    def get_security_settings(self) -> Dict[str, Any]:
        """Extract security-related settings from config."""
        security_settings = {}
        
        # Database security
        db_config = self.get_database_config()
        if db_config:
            security_settings["db"] = {
                "port": db_config.get("port"),
                "host": db_config.get("host"),
                "db_name": db_config.get("db_name"),
                "max_connections": db_config.get("max_connections"),
                "pool_size": db_config.get("pool_size")
            }
        
        # Auth security
        auth_config = self.get_auth_config()
        if auth_config:
            security_settings["auth"] = {
                "jwt_expiry": auth_config.get("jwt_expiry"),
                "refresh_token_rotation_enabled": auth_config.get("refresh_token_rotation_enabled"),
                "secure_password_change_enabled": auth_config.get("secure_password_change_enabled"),
                "enable_signup": auth_config.get("enable_signup"),
                "enable_anonymous_users": auth_config.get("enable_anonymous_users")
            }
        
        # API security
        api_config = self.get_api_config()
        if api_config:
            security_settings["api"] = {
                "port": api_config.get("port"),
                "schemas": api_config.get("schemas"),
                "extra_search_path": api_config.get("extra_search_path"),
                "max_rows": api_config.get("max_rows")
            }
        
        return security_settings
    
    def validate_security_config(self) -> List[Dict[str, Any]]:
        """Validate security configuration and return issues."""
        issues = []
        
        # Check auth configuration
        auth_config = self.get_auth_config()
        if auth_config:
            # Check JWT expiry
            jwt_expiry = auth_config.get("jwt_expiry")
            if jwt_expiry and jwt_expiry > 3600:  # More than 1 hour
                issues.append({
                    "type": "auth",
                    "severity": "MEDIUM",
                    "title": "Long JWT expiry time",
                    "description": f"JWT expiry is set to {jwt_expiry} seconds",
                    "recommendation": "Consider shorter JWT expiry for better security"
                })
            
            # Check if signup is enabled
            if auth_config.get("enable_signup", True):
                issues.append({
                    "type": "auth",
                    "severity": "LOW",
                    "title": "User signup enabled",
                    "description": "User signup is enabled in configuration",
                    "recommendation": "Consider disabling signup if not needed"
                })
        
        # Check API configuration
        api_config = self.get_api_config()
        if api_config:
            # Check max_rows limit
            max_rows = api_config.get("max_rows")
            if max_rows and max_rows > 1000:
                issues.append({
                    "type": "api",
                    "severity": "MEDIUM",
                    "title": "High max_rows limit",
                    "description": f"API max_rows is set to {max_rows}",
                    "recommendation": "Consider lower max_rows limit to prevent large data dumps"
                })
        
        return issues
    
    def get_database_url(self) -> Optional[str]:
        """Construct database URL from config."""
        db_config = self.get_database_config()
        if not db_config:
            return None
        
        host = db_config.get("host", "localhost")
        port = db_config.get("port", 54322)
        db_name = db_config.get("db_name", "postgres")
        
        return f"postgresql://postgres:postgres@{host}:{port}/{db_name}"
    
    def get_api_url(self) -> Optional[str]:
        """Construct API URL from config."""
        api_config = self.get_api_config()
        if not api_config:
            return None
        
        port = api_config.get("port", 54321)
        return f"http://localhost:{port}"
    
    def get_auth_url(self) -> Optional[str]:
        """Construct auth URL from config."""
        auth_config = self.get_auth_config()
        if not auth_config:
            return None
        
        port = auth_config.get("port", 54321)
        return f"http://localhost:{port}/auth/v1"
    
    def get_storage_url(self) -> Optional[str]:
        """Construct storage URL from config."""
        storage_config = self.get_storage_config()
        if not storage_config:
            return None
        
        port = storage_config.get("port", 54321)
        return f"http://localhost:{port}/storage/v1"
    
    def get_realtime_url(self) -> Optional[str]:
        """Construct realtime URL from config."""
        realtime_config = self.get_realtime_config()
        if not realtime_config:
            return None
        
        port = realtime_config.get("port", 54321)
        return f"ws://localhost:{port}/realtime/v1"
    
    def get_all_urls(self) -> Dict[str, str]:
        """Get all service URLs from config."""
        urls = {}
        
        if self.get_database_url():
            urls["database"] = self.get_database_url()
        
        if self.get_api_url():
            urls["api"] = self.get_api_url()
        
        if self.get_auth_url():
            urls["auth"] = self.get_auth_url()
        
        if self.get_storage_url():
            urls["storage"] = self.get_storage_url()
        
        if self.get_realtime_url():
            urls["realtime"] = self.get_realtime_url()
        
        return urls
    
    def export_config_summary(self) -> Dict[str, Any]:
        """Export a summary of the configuration."""
        return {
            "project_id": self.get_project_id(),
            "database_config": self.get_database_config(),
            "auth_config": self.get_auth_config(),
            "api_config": self.get_api_config(),
            "storage_config": self.get_storage_config(),
            "realtime_config": self.get_realtime_config(),
            "functions_config": self.get_edge_functions_config(),
            "security_settings": self.get_security_settings(),
            "service_urls": self.get_all_urls(),
            "security_issues": self.validate_security_config()
        }
