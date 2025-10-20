"""
Configuration management for Supabase Security Suite.
"""

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Any
import toml


@dataclass
class ScanSettings:
    """Scan configuration settings."""
    
    # File scanning
    max_file_size: int = 10 * 1024 * 1024  # 10MB
    scan_extensions: List[str] = field(default_factory=lambda: [
        ".ts", ".tsx", ".js", ".jsx", ".sql", ".env", ".yaml", ".yml", ".toml", ".md", ".sh"
    ])
    
    # Network scanning
    default_ports: List[int] = field(default_factory=lambda: [22, 80, 443, 5432, 54321, 54322, 54323, 54324])
    timeout_seconds: int = 30
    
    # Feature toggles
    enable_semgrep: bool = True
    enable_ai_recommendations: bool = False
    enable_docker_scanning: bool = False
    enable_rls_simulation: bool = True
    enable_secret_scanning: bool = True
    enable_git_leak_detection: bool = True
    
    # Security settings
    allow_external_scans: bool = False
    require_authentication: bool = True
    max_concurrent_scans: int = 3


@dataclass
class AIConfig:
    """AI provider configuration."""
    
    provider: str = "none"  # "openai", "openrouter", "anthropic", "none"
    openai_api_key: Optional[str] = None
    openrouter_api_key: Optional[str] = None
    anthropic_api_key: Optional[str] = None
    openrouter_model: str = "anthropic/claude-3-haiku"
    enabled: bool = False


@dataclass
class JiraConfig:
    """Jira integration configuration."""
    
    enabled: bool = False
    url: str = ""
    username: str = ""
    api_token: str = ""
    project_key: str = ""
    issue_type: str = "Bug"


@dataclass
class DashboardConfig:
    """Dashboard configuration."""
    
    host: str = "0.0.0.0"
    port: int = 8080
    debug: bool = False
    enable_cors: bool = True
    session_timeout: int = 3600


@dataclass
class SupabaseConfig:
    """Supabase-specific configuration."""
    
    project_url: Optional[str] = None
    database_url: Optional[str] = None
    anon_key: Optional[str] = None
    service_role_key: Optional[str] = None
    config_file_path: Optional[str] = None


@dataclass
class SecurityConfig:
    """Main configuration class for the security suite."""
    
    scan_settings: ScanSettings = field(default_factory=ScanSettings)
    ai_config: AIConfig = field(default_factory=AIConfig)
    jira_config: JiraConfig = field(default_factory=JiraConfig)
    dashboard_config: DashboardConfig = field(default_factory=DashboardConfig)
    supabase_config: SupabaseConfig = field(default_factory=SupabaseConfig)
    
    @classmethod
    def from_file(cls, config_path: str) -> "SecurityConfig":
        """Load configuration from JSON file."""
        config_file = Path(config_path)
        
        if not config_file.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        
        with open(config_file, 'r') as f:
            data = json.load(f)
        
        return cls.from_dict(data)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SecurityConfig":
        """Create configuration from dictionary."""
        scan_data = data.get("scan_settings", {})
        ai_data = data.get("ai", {})
        jira_data = data.get("jira_integration", {})
        dashboard_data = data.get("dashboard", {})
        supabase_data = data.get("supabase", {})
        
        return cls(
            scan_settings=ScanSettings(
                max_file_size=scan_data.get("max_file_size", 10 * 1024 * 1024),
                scan_extensions=scan_data.get("scan_extensions", [
                    ".ts", ".tsx", ".js", ".jsx", ".sql", ".env", ".yaml", ".yml", ".toml", ".md", ".sh"
                ]),
                default_ports=scan_data.get("default_ports", [22, 80, 443, 5432, 54321, 54322, 54323, 54324]),
                timeout_seconds=scan_data.get("timeout_seconds", 30),
                enable_semgrep=scan_data.get("enable_semgrep", True),
                enable_ai_recommendations=scan_data.get("enable_ai_recommendations", False),
                enable_docker_scanning=scan_data.get("enable_docker_scanning", False),
                enable_rls_simulation=scan_data.get("enable_rls_simulation", True),
                enable_secret_scanning=scan_data.get("enable_secret_scanning", True),
                enable_git_leak_detection=scan_data.get("enable_git_leak_detection", True),
                allow_external_scans=scan_data.get("allow_external_scans", False),
                require_authentication=scan_data.get("require_authentication", True),
                max_concurrent_scans=scan_data.get("max_concurrent_scans", 3)
            ),
            ai_config=AIConfig(
                provider=ai_data.get("provider", "none"),
                openai_api_key=ai_data.get("openai_api_key"),
                openrouter_api_key=ai_data.get("openrouter_api_key"),
                anthropic_api_key=ai_data.get("anthropic_api_key"),
                openrouter_model=ai_data.get("openrouter_model", "anthropic/claude-3-haiku"),
                enabled=ai_data.get("enabled", False)
            ),
            jira_config=JiraConfig(
                enabled=jira_data.get("enabled", False),
                url=jira_data.get("url", ""),
                username=jira_data.get("email", ""),
                api_token=jira_data.get("token", ""),
                project_key=jira_data.get("project_key", ""),
                issue_type=jira_data.get("issue_type", "Bug")
            ),
            dashboard_config=DashboardConfig(
                host=dashboard_data.get("host", "0.0.0.0"),
                port=dashboard_data.get("port", 8080),
                debug=dashboard_data.get("debug", False),
                enable_cors=dashboard_data.get("enable_cors", True),
                session_timeout=dashboard_data.get("session_timeout", 3600)
            ),
            supabase_config=SupabaseConfig(
                project_url=supabase_data.get("project_url"),
                database_url=supabase_data.get("database_url"),
                anon_key=supabase_data.get("anon_key"),
                service_role_key=supabase_data.get("service_role_key"),
                config_file_path=supabase_data.get("config_file_path")
            )
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            "scan_settings": {
                "max_file_size": self.scan_settings.max_file_size,
                "scan_extensions": self.scan_settings.scan_extensions,
                "default_ports": self.scan_settings.default_ports,
                "timeout_seconds": self.scan_settings.timeout_seconds,
                "enable_semgrep": self.scan_settings.enable_semgrep,
                "enable_ai_recommendations": self.scan_settings.enable_ai_recommendations,
                "enable_docker_scanning": self.scan_settings.enable_docker_scanning,
                "enable_rls_simulation": self.scan_settings.enable_rls_simulation,
                "enable_secret_scanning": self.scan_settings.enable_secret_scanning,
                "enable_git_leak_detection": self.scan_settings.enable_git_leak_detection,
                "allow_external_scans": self.scan_settings.allow_external_scans,
                "require_authentication": self.scan_settings.require_authentication,
                "max_concurrent_scans": self.scan_settings.max_concurrent_scans
            },
            "ai": {
                "provider": self.ai_config.provider,
                "openai_api_key": self.ai_config.openai_api_key,
                "openrouter_api_key": self.ai_config.openrouter_api_key,
                "anthropic_api_key": self.ai_config.anthropic_api_key,
                "openrouter_model": self.ai_config.openrouter_model,
                "enabled": self.ai_config.enabled
            },
            "jira_integration": {
                "enabled": self.jira_config.enabled,
                "url": self.jira_config.url,
                "email": self.jira_config.username,
                "token": self.jira_config.api_token,
                "project_key": self.jira_config.project_key,
                "issue_type": self.jira_config.issue_type
            },
            "dashboard": {
                "host": self.dashboard_config.host,
                "port": self.dashboard_config.port,
                "debug": self.dashboard_config.debug,
                "enable_cors": self.dashboard_config.enable_cors,
                "session_timeout": self.dashboard_config.session_timeout
            },
            "supabase": {
                "project_url": self.supabase_config.project_url,
                "database_url": self.supabase_config.database_url,
                "anon_key": self.supabase_config.anon_key,
                "service_role_key": self.supabase_config.service_role_key,
                "config_file_path": self.supabase_config.config_file_path
            }
        }
    
    def save_to_file(self, config_path: str) -> None:
        """Save configuration to JSON file."""
        config_file = Path(config_path)
        config_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(config_file, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)
    
    def load_from_environment(self) -> None:
        """Load configuration from environment variables."""
        # AI Configuration
        if os.getenv("OPENAI_API_KEY"):
            self.ai_config.openai_api_key = os.getenv("OPENAI_API_KEY")
            self.ai_config.provider = "openai"
            self.ai_config.enabled = True
        
        if os.getenv("OPENROUTER_API_KEY"):
            self.ai_config.openrouter_api_key = os.getenv("OPENROUTER_API_KEY")
            self.ai_config.provider = "openrouter"
            self.ai_config.enabled = True
        
        if os.getenv("ANTHROPIC_API_KEY"):
            self.ai_config.anthropic_api_key = os.getenv("ANTHROPIC_API_KEY")
            self.ai_config.provider = "anthropic"
            self.ai_config.enabled = True
        
        # Jira Configuration
        if os.getenv("JIRA_URL"):
            self.jira_config.url = os.getenv("JIRA_URL")
            self.jira_config.enabled = True
        
        if os.getenv("JIRA_EMAIL"):
            self.jira_config.username = os.getenv("JIRA_EMAIL")
        
        if os.getenv("JIRA_TOKEN"):
            self.jira_config.api_token = os.getenv("JIRA_TOKEN")
        
        # Supabase Configuration
        if os.getenv("SUPABASE_URL"):
            self.supabase_config.project_url = os.getenv("SUPABASE_URL")
        
        if os.getenv("SUPABASE_DB_URL"):
            self.supabase_config.database_url = os.getenv("SUPABASE_DB_URL")
        
        if os.getenv("SUPABASE_ANON_KEY"):
            self.supabase_config.anon_key = os.getenv("SUPABASE_ANON_KEY")
        
        if os.getenv("SUPABASE_SERVICE_ROLE_KEY"):
            self.supabase_config.service_role_key = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
    
    def load_supabase_config(self, project_path: str) -> None:
        """Load Supabase configuration from config.toml file."""
        config_path = Path(project_path) / "supabase" / "config.toml"
        
        if not config_path.exists():
            return
        
        try:
            config_data = toml.load(config_path)
            
            # Extract relevant configuration
            if "project_id" in config_data:
                self.supabase_config.config_file_path = str(config_path)
            
            # Load database configuration
            if "db" in config_data:
                db_config = config_data["db"]
                if "port" in db_config and not self.supabase_config.database_url:
                    # Construct database URL if not provided
                    host = db_config.get("host", "localhost")
                    port = db_config.get("port", 54322)
                    db_name = db_config.get("db_name", "postgres")
                    self.supabase_config.database_url = f"postgresql://postgres:postgres@{host}:{port}/{db_name}"
            
        except Exception as e:
            print(f"Warning: Could not parse Supabase config.toml: {e}")


def create_default_config() -> SecurityConfig:
    """Create a default configuration."""
    config = SecurityConfig()
    config.load_from_environment()
    return config
