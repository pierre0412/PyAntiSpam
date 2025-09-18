"""Configuration manager for PyAntiSpam"""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from dotenv import load_dotenv


class ConfigManager:
    """Manages configuration loading and validation"""

    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or "config.yaml"
        self.config: Dict[str, Any] = {}
        self._load_config()
        self._load_env_vars()

    def _load_config(self):
        """Load configuration from YAML file"""
        config_file = Path(self.config_path)

        if not config_file.exists():
            raise FileNotFoundError(
                f"Configuration file not found: {self.config_path}\n"
                f"Please copy config.yaml.example to config.yaml and customize it."
            )

        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                self.config = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML in config file: {e}")

    def _load_env_vars(self):
        """Load environment variables from .env file if it exists"""
        env_file = Path(".env")
        if env_file.exists():
            load_dotenv(env_file)

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by key (supports dot notation)"""
        keys = key.split('.')
        value = self.config

        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default

        return value

    def get_email_accounts(self) -> list:
        """Get email account configurations"""
        accounts = self.get('email_accounts', [])

        # Resolve password environment variables
        for account in accounts:
            if 'password_env' in account:
                env_var = account['password_env']
                password = os.getenv(env_var)
                if not password:
                    raise ValueError(
                        f"Environment variable {env_var} not found for account '{account.get('name', 'unknown')}'"
                    )
                account['password'] = password

        return accounts

    def get_llm_config(self) -> Dict[str, Any]:
        """Get LLM configuration with API key from environment"""
        llm_config = self.get('llm', {})

        if 'api_key_env' in llm_config:
            env_var = llm_config['api_key_env']
            api_key = os.getenv(env_var)
            if not api_key:
                raise ValueError(
                    f"Environment variable {env_var} not found for LLM API key"
                )
            llm_config['api_key'] = api_key

        return llm_config

    def validate_config(self):
        """Validate configuration completeness and correctness"""
        errors = []

        # Check required sections
        required_sections = ['llm', 'email_accounts', 'detection', 'actions']
        for section in required_sections:
            if not self.get(section):
                errors.append(f"Missing required section: {section}")

        # Validate email accounts
        accounts = self.get('email_accounts', [])
        if not accounts:
            errors.append("No email accounts configured")

        for i, account in enumerate(accounts):
            required_fields = ['name', 'server', 'port', 'username', 'password_env']
            for field in required_fields:
                if field not in account:
                    errors.append(f"Email account {i}: missing field '{field}'")

        # Validate LLM config
        llm_config = self.get('llm', {})
        required_llm_fields = ['provider', 'model', 'api_key_env']
        for field in required_llm_fields:
            if field not in llm_config:
                errors.append(f"LLM config: missing field '{field}'")

        if errors:
            raise ValueError("Configuration validation failed:\n" + "\n".join(f"  - {error}" for error in errors))

        return True