"""
Configuration management using Pydantic Settings.
Handles environment variables and application configuration.
"""

from typing import Optional, List
from pydantic import Field, validator
from pydantic_settings import BaseSettings
import os


class DatabaseSettings(BaseSettings):
    """Database configuration settings."""
    
    url: str = Field(
        default="postgresql://test:test@localhost:5432/test",
        description="PostgreSQL database URL"
    )
    
    echo: bool = Field(
        default=False,
        description="Enable SQLAlchemy query logging"
    )
    pool_size: int = Field(
        default=10,
        description="Database connection pool size"
    )
    max_overflow: int = Field(
        default=20,
        description="Maximum overflow connections"
    )
    pool_timeout: int = Field(
        default=30,
        description="Connection pool timeout in seconds"
    )
    pool_recycle: int = Field(
        default=3600,
        description="Connection pool recycle time in seconds"
    )
    
    class Config:
        env_prefix = "DATABASE_"


class RedisSettings(BaseSettings):
    """Redis configuration settings."""
    
    url: str = Field(
        default="redis://localhost:6379/0",
        description="Redis connection URL"
    )
    max_connections: int = Field(
        default=100,
        description="Maximum Redis connections"
    )
    socket_timeout: int = Field(
        default=5,
        description="Redis socket timeout in seconds"
    )
    socket_connect_timeout: int = Field(
        default=5,
        description="Redis socket connect timeout in seconds"
    )
    retry_on_timeout: bool = Field(
        default=True,
        description="Retry on Redis timeout"
    )
    
    class Config:
        env_prefix = "REDIS_"


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
    database: DatabaseSettings = DatabaseSettings()
    
    # Redis settings
    redis: RedisSettings = RedisSettings()
    
    # Security settings
    api_key_secret: str = "default-secret"
    
    # External API keys
    gemini_api_key: str = "test-key"
    guvi_api_key: str = "test-key"
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False
        extra = "ignore"  # Ignore extra fields to handle legacy config
    
    def is_development(self) -> bool:
        """Check if running in development mode."""
        return self.environment == "development"
    
    def is_production(self) -> bool:
        """Check if running in production mode."""
        return self.environment == "production"


# Global settings instance
settings = Settings()