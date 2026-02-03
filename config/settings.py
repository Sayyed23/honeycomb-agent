"""
Configuration management using Pydantic Settings.
Handles environment variables and application configuration.
"""

from typing import Optional, List
from pydantic import Field
from pydantic_settings import BaseSettings
import os


class Settings(BaseSettings):
    """Main application settings."""
    
    # Application metadata
    app_name: str = "Agentic Honeypot API"
    app_version: str = "1.0.0"
    debug: bool = False
    environment: str = "production"
    
    # Server settings
    host: str = "0.0.0.0"
    port: int = 8000
    workers: int = 1
    
    # Database settings
    database_url: str = "postgresql://test:test@localhost:5432/test"
    
    # Security settings
    api_key_secret: str = "default-secret"
    
    # External API keys
    gemini_api_key: str = "test-key"
    guvi_api_key: str = "test-key"
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False
    
    def is_development(self) -> bool:
        """Check if running in development mode."""
        return self.environment == "development"
    
    def is_production(self) -> bool:
        """Check if running in production mode."""
        return self.environment == "production"


# Global settings instance
settings = Settings()