"""
Configuration management for the Supabase Security Suite.
"""

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field, SecretStr
from pydantic_settings import BaseSettings


class DatabaseConfig(BaseModel):
    """Database connection configuration."""

    host: str = Field("localhost", description="Database host")
    port: int = Field(5432, description="Database port")
    database: str = Field("postgres", description="Database name")
    user: str = Field("postgres", description="Database user")
    password: SecretStr = Field(SecretStr(""), description="Database password")
    ssl_mode: str = Field("prefer", description="SSL mode (disable/prefer/require)")


class SupabaseConfig(BaseModel):
    """Supabase-specific configuration."""

    url: str = Field("", description="Supabase project URL")
    anon_key: SecretStr = Field(SecretStr(""), description="Anonymous (public) API key")
    service_role_key: SecretStr = Field(SecretStr(""), description="Service role (admin) API key")
    jwt_secret: Optional[SecretStr] = Field(None, description="JWT secret for token generation")


class RLSScannerConfig(BaseModel):
    """Configuration for RLS policy scanner."""

    enabled: bool = True
    check_indexes: bool = Field(
        True, description="Check for missing indexes on policy columns"
    )
    check_asymmetric_policies: bool = Field(
        True, description="Check for asymmetric USING/WITH CHECK clauses"
    )
    exclude_schemas: list[str] = Field(
        default_factory=lambda: ["pg_catalog", "information_schema"],
        description="Schemas to exclude from scanning",
    )


class SecretsScannerConfig(BaseModel):
    """Configuration for secrets scanner."""

    enabled: bool = True
    scan_git_history: bool = Field(
        False, description="Scan git history for leaked secrets (can be slow)"
    )
    entropy_threshold: float = Field(
        4.5, description="Minimum entropy for high-entropy string detection"
    )
    max_file_size_mb: int = Field(
        10, description="Skip files larger than this size"
    )
    exclude_patterns: list[str] = Field(
        default_factory=lambda: [
            "*.lock",
            "*.log",
            "node_modules/*",
            ".git/*",
            "venv/*",
            "*.pyc",
        ],
        description="File patterns to exclude",
    )


class DockerScannerConfig(BaseModel):
    """Configuration for Docker scanner."""

    enabled: bool = True
    check_exposed_ports: bool = True
    check_privileged: bool = True
    check_default_passwords: bool = True


class GraphQLScannerConfig(BaseModel):
    """Configuration for GraphQL scanner."""

    enabled: bool = True
    check_introspection: bool = True
    check_anonymous_access: bool = True


class AIConfig(BaseModel):
    """AI provider configuration."""

    provider: str = Field("none", description="AI provider: openai, openrouter, or none")
    openai_api_key: Optional[SecretStr] = None
    openrouter_api_key: Optional[SecretStr] = None
    model: str = Field("gpt-4", description="Model to use for AI recommendations")
    enabled: bool = False


class JiraIntegrationConfig(BaseModel):
    """Jira integration configuration."""

    enabled: bool = False
    url: Optional[str] = None
    username: Optional[str] = None
    api_token: Optional[SecretStr] = None
    project_key: Optional[str] = None


class SlackIntegrationConfig(BaseModel):
    """Slack integration configuration."""

    enabled: bool = False
    webhook_url: Optional[SecretStr] = None


class ScannersConfig(BaseModel):
    """Configuration for all scanners."""

    rls: RLSScannerConfig = Field(default_factory=RLSScannerConfig)
    secrets: SecretsScannerConfig = Field(default_factory=SecretsScannerConfig)
    docker: DockerScannerConfig = Field(default_factory=DockerScannerConfig)
    graphql: GraphQLScannerConfig = Field(default_factory=GraphQLScannerConfig)


class IntegrationsConfig(BaseModel):
    """Configuration for external integrations."""

    jira: JiraIntegrationConfig = Field(default_factory=JiraIntegrationConfig)
    slack: SlackIntegrationConfig = Field(default_factory=SlackIntegrationConfig)


class Config(BaseSettings):
    """Main configuration class for the Supabase Security Suite."""

    # Project settings
    project_name: str = Field("Supabase Security Scan", description="Project name")
    target: Path = Field(Path.cwd(), description="Target directory to scan")

    # Database connection
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)

    # Supabase settings
    supabase: SupabaseConfig = Field(default_factory=SupabaseConfig)

    # Scanner configurations
    scanners: ScannersConfig = Field(default_factory=ScannersConfig)

    # AI configuration
    ai: AIConfig = Field(default_factory=AIConfig)

    # Integrations
    integrations: IntegrationsConfig = Field(default_factory=IntegrationsConfig)

    # Output settings
    output_format: str = Field("json", description="Output format: json, markdown, pdf, sarif")
    output_file: Optional[Path] = None
    verbose: bool = False

    class Config:
        env_prefix = "SUPABASE_SECURITY_"
        env_nested_delimiter = "__"
        case_sensitive = False
        extra = "ignore"  # Ignore unknown fields for backwards compatibility

    @classmethod
    def from_file(cls, config_path: Path | str) -> "Config":
        """Load configuration from a JSON file."""
        config_path = Path(config_path) if isinstance(config_path, str) else config_path
        if not config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")

        with open(config_path) as f:
            data = json.load(f)

        return cls(**data)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Config":
        """Load configuration from a dictionary."""
        return cls(**data)

    def to_dict(self, exclude_secrets: bool = True) -> Dict[str, Any]:
        """Export configuration to a dictionary."""
        if exclude_secrets:
            return json.loads(
                self.model_dump_json(
                    exclude={
                        "database": {"password"},
                        "supabase": {"anon_key", "service_role_key", "jwt_secret"},
                        "ai": {"openai_api_key", "openrouter_api_key"},
                        "integrations": {
                            "jira": {"api_token"},
                            "slack": {"webhook_url"},
                        },
                    }
                )
            )
        return json.loads(self.model_dump_json())

    def save_to_file(self, config_path: Path, exclude_secrets: bool = True) -> None:
        """Save configuration to a JSON file."""
        with open(config_path, "w") as f:
            json.dump(self.to_dict(exclude_secrets=exclude_secrets), f, indent=2)

    def get_database_url(self) -> str:
        """Get database connection URL."""
        password = self.database.password.get_secret_value()
        return (
            f"postgresql://{self.database.user}:{password}"
            f"@{self.database.host}:{self.database.port}/{self.database.database}"
        )


def load_config(
    config_path: Optional[Path] = None,
    overrides: Optional[Dict[str, Any]] = None,
) -> Config:
    """
    Load configuration from file and environment variables.

    Priority (highest to lowest):
    1. Provided overrides
    2. Config file
    3. Environment variables
    4. Default values
    """
    # Start with defaults from environment variables
    config_data = {}

    # Load from file if provided
    if config_path:
        if not config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        with open(config_path) as f:
            config_data = json.load(f)

    # Apply overrides
    if overrides:
        config_data.update(overrides)

    return Config(**config_data)


def create_default_config(output_path: Path) -> None:
    """Create a default configuration file."""
    default_config = {
        "project_name": "Supabase Security Scan",
        "database": {
            "host": "localhost",
            "port": 5432,
            "database": "postgres",
            "user": "postgres",
            "password": "your-password-here",
        },
        "supabase": {
            "url": "http://localhost:8000",
            "anon_key": "your-anon-key-here",
            "service_role_key": "your-service-role-key-here",
            "jwt_secret": "your-jwt-secret-here",
        },
        "scanners": {
            "rls": {"enabled": True, "check_indexes": True},
            "secrets": {
                "enabled": True,
                "scan_git_history": False,
                "entropy_threshold": 4.5,
            },
            "docker": {"enabled": True},
            "graphql": {"enabled": True},
        },
        "ai": {
            "provider": "none",
            "model": "gpt-4",
            "enabled": False,
        },
        "integrations": {
            "jira": {"enabled": False},
            "slack": {"enabled": False},
        },
    }

    with open(output_path, "w") as f:
        json.dump(default_config, f, indent=2)

    print(f"✅ Default configuration created at: {output_path}")
    print("⚠️  Please edit the file to add your credentials before running scans.")

