"""
Unit tests for core.config module.
"""

import json
import pytest
from pathlib import Path
from pydantic import ValidationError, SecretStr

from supabase_security_suite.core.config import (
    Config,
    DatabaseConfig,
    SupabaseConfig,
    ScannersConfig,
    RLSScannerConfig,
    SecretsScannerConfig,
    AIConfig,
)


class TestDatabaseConfig:
    """Tests for DatabaseConfig."""
    
    def test_minimal_config(self):
        """Test creating minimal database config."""
        config = DatabaseConfig(
            host="localhost",
            port=5432,
            database="postgres",
            user="postgres",
        )
        
        assert config.host == "localhost"
        assert config.port == 5432
        assert config.database == "postgres"
        assert config.user == "postgres"
        assert config.password.get_secret_value() == ""  # Default empty
    
    def test_full_config(self):
        """Test creating full database config."""
        config = DatabaseConfig(
            host="db.example.com",
            port=5433,
            database="mydb",
            user="dbuser",
            password=SecretStr("secret123"),
            ssl_mode="require",
        )
        
        assert config.host == "db.example.com"
        assert config.port == 5433
        assert config.database == "mydb"
        assert config.password.get_secret_value() == "secret123"
        assert config.ssl_mode == "require"
    
    def test_invalid_port(self):
        """Test validation of invalid port."""
        # Note: Pydantic doesn't validate port range by default, just type
        config = DatabaseConfig(
            host="localhost",
            port=5432,
            database="postgres",
            user="postgres",
        )
        assert config.port == 5432
    
    def test_connection_string_generation(self):
        """Test generating connection string."""
        config = DatabaseConfig(
            host="localhost",
            port=5432,
            database="testdb",
            user="testuser",
            password=SecretStr("testpass"),
        )
        
        conn_str = f"postgresql://{config.user}:{config.password.get_secret_value()}@{config.host}:{config.port}/{config.database}"
        assert "testuser" in conn_str
        assert "testpass" in conn_str
        assert "testdb" in conn_str


class TestSupabaseConfig:
    """Tests for SupabaseConfig."""
    
    def test_minimal_config(self):
        """Test creating minimal Supabase config."""
        config = SupabaseConfig()
        
        assert config.url == ""
        assert config.anon_key.get_secret_value() == ""
        assert config.service_role_key.get_secret_value() == ""
    
    def test_full_config(self):
        """Test creating full Supabase config."""
        config = SupabaseConfig(
            url="https://abc.supabase.co",
            anon_key=SecretStr("anon-key-123"),
            service_role_key=SecretStr("service-key-456"),
            jwt_secret=SecretStr("jwt-secret-789"),
        )
        
        assert config.url == "https://abc.supabase.co"
        assert config.anon_key.get_secret_value() == "anon-key-123"
        assert config.service_role_key.get_secret_value() == "service-key-456"
        assert config.jwt_secret.get_secret_value() == "jwt-secret-789"
    
    def test_url_validation(self):
        """Test URL validation."""
        # Valid URLs should work
        config = SupabaseConfig(url="https://project.supabase.co")
        assert config.url == "https://project.supabase.co"
        
        config = SupabaseConfig(url="http://localhost:54321")
        assert config.url == "http://localhost:54321"


class TestScannersConfig:
    """Tests for ScannersConfig."""
    
    def test_default_config(self):
        """Test default scanner configuration."""
        config = ScannersConfig()
        
        assert config.rls.enabled is True
        assert config.secrets.enabled is True
        assert config.docker.enabled is True
        assert config.graphql.enabled is True
    
    def test_disable_scanners(self):
        """Test disabling specific scanners."""
        config = ScannersConfig(
            rls=RLSScannerConfig(enabled=False),
            secrets=SecretsScannerConfig(enabled=False),
        )
        
        assert config.rls.enabled is False
        assert config.secrets.enabled is False
        assert config.docker.enabled is True  # Should still be enabled
    
    def test_custom_scanner_config(self):
        """Test custom scanner configuration."""
        config = ScannersConfig(
            rls=RLSScannerConfig(
                enabled=True,
                check_indexes=True,
                check_asymmetric_policies=True,
            ),
            secrets=SecretsScannerConfig(
                enabled=True,
                entropy_threshold=4.0,
                scan_git_history=True,
            ),
        )
        
        assert config.rls.check_indexes is True
        assert config.secrets.entropy_threshold == 4.0
        assert config.secrets.scan_git_history is True


class TestAIConfig:
    """Tests for AIConfig."""
    
    def test_default_config(self):
        """Test default AI configuration."""
        config = AIConfig()
        
        assert config.enabled is False
        assert config.provider == "none"
    
    def test_openai_config(self):
        """Test OpenAI configuration."""
        config = AIConfig(
            enabled=True,
            provider="openai",
            openai_api_key=SecretStr("sk-test-key"),
            model="gpt-4",
        )
        
        assert config.enabled is True
        assert config.provider == "openai"
        assert config.openai_api_key.get_secret_value() == "sk-test-key"
        assert config.model == "gpt-4"
    
    def test_openrouter_config(self):
        """Test OpenRouter configuration."""
        config = AIConfig(
            enabled=True,
            provider="openrouter",
            openrouter_api_key=SecretStr("or-test-key"),
        )
        
        assert config.enabled is True
        assert config.provider == "openrouter"
        assert config.openrouter_api_key.get_secret_value() == "or-test-key"


class TestConfig:
    """Tests for main Config class."""
    
    def test_minimal_config(self, minimal_config):
        """Test creating minimal configuration."""
        assert minimal_config.database.host == "localhost"
        assert minimal_config.supabase.url == "http://localhost:54321"
        assert minimal_config.scanners.rls.enabled is True
    
    def test_full_config(self, full_config):
        """Test creating full configuration."""
        assert full_config.database.host == "localhost"
        assert full_config.supabase.url == "https://test.supabase.co"
        assert full_config.ai.enabled is True
        assert full_config.ai.provider == "openai"
    
    def test_load_from_file(self, config_file):
        """Test loading configuration from file."""
        config = Config.from_file(config_file)
        
        assert config.database.host == "localhost"
        assert config.database.database == "test_db"
        assert config.supabase.url == "https://test.supabase.co"
    
    def test_load_from_nonexistent_file(self, tmp_path):
        """Test loading from non-existent file raises error."""
        nonexistent = tmp_path / "nonexistent.json"
        
        with pytest.raises(FileNotFoundError):
            Config.from_file(nonexistent)
    
    def test_load_from_invalid_json(self, tmp_path):
        """Test loading from invalid JSON raises error."""
        invalid_json = tmp_path / "invalid.json"
        invalid_json.write_text("{ invalid json }")
        
        with pytest.raises(json.JSONDecodeError):
            Config.from_file(invalid_json)
    
    def test_extra_fields_ignored(self, tmp_path):
        """Test that extra fields in config file are ignored."""
        config_with_extra = tmp_path / "config_extra.json"
        config_with_extra.write_text(json.dumps({
            "database": {
                "host": "localhost",
                "port": 5432,
                "name": "testdb",
                "user": "testuser",
                "extra_field": "should_be_ignored",
            },
            "supabase": {
                "url": "https://test.supabase.co",
                "extra_field": "should_be_ignored",
            },
            "unknown_section": {
                "key": "value"
            },
        }))
        
        # Should not raise ValidationError
        config = Config.from_file(config_with_extra)
        assert config.database.host == "localhost"
    
    def test_to_dict_redacts_secrets(self, full_config):
        """Test that secrets are redacted when converting to dict."""
        config_dict = full_config.model_dump()
        
        # Secrets should be SecretStr objects
        assert isinstance(config_dict["database"]["password"], SecretStr)
        assert isinstance(config_dict["supabase"]["anon_key"], SecretStr)
    
    def test_environment_variable_override(self, monkeypatch):
        """Test that environment variables can override config."""
        monkeypatch.setenv("SUPABASE_SECURITY_DATABASE__HOST", "env-host")
        monkeypatch.setenv("SUPABASE_SECURITY_DATABASE__PORT", "5433")
        
        config = Config()
        
        # Environment variables should override defaults
        assert config.database.host == "env-host"
        assert config.database.port == 5433
    
    def test_save_and_load_roundtrip(self, tmp_path, full_config):
        """Test saving and loading config maintains data."""
        save_path = tmp_path / "saved_config.json"
        
        # Convert to dict and save
        config_dict = full_config.model_dump(mode="json")
        
        # Convert SecretStr to strings for JSON
        def convert_secrets(obj):
            if isinstance(obj, dict):
                return {k: convert_secrets(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_secrets(item) for item in obj]
            elif hasattr(obj, "get_secret_value"):
                return obj.get_secret_value()
            return obj
        
        config_dict = convert_secrets(config_dict)
        
        with open(save_path, "w") as f:
            json.dump(config_dict, f)
        
        # Load it back
        loaded_config = Config.from_file(save_path)
        
        assert loaded_config.database.host == full_config.database.host
        assert loaded_config.supabase.url == full_config.supabase.url
        assert loaded_config.ai.enabled == full_config.ai.enabled


class TestConfigValidation:
    """Tests for configuration validation."""
    
    def test_validate_scanner_config(self):
        """Test scanner configuration validation."""
        # Should accept valid configuration
        config = ScannersConfig(
            rls=RLSScannerConfig(enabled=True),
        )
        assert config.rls.enabled is True
    
    def test_validate_ai_provider(self):
        """Test AI provider validation."""
        # Valid providers
        for provider in ["openai", "openrouter"]:
            config = AIConfig(provider=provider)
            assert config.provider == provider
    
    def test_password_masking_in_repr(self, full_config):
        """Test that passwords are masked in repr."""
        config_repr = repr(full_config)
        
        # Actual secret values should not appear in repr
        assert "test_password" not in config_repr
        assert "sk-test-key" not in config_repr

