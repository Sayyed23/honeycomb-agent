"""
Test configuration settings using SQLite for database and mock Redis.
"""

from config.settings import Settings, DatabaseSettings, RedisSettings


class TestDatabaseSettings(DatabaseSettings):
    """Test database configuration using SQLite."""
    
    url: str = "sqlite:///./test.db"
    echo: bool = False
    pool_size: int = 1
    max_overflow: int = 0
    pool_timeout: int = 30
    pool_recycle: int = 3600


class TestRedisSettings(RedisSettings):
    """Test Redis configuration - will be mocked."""
    
    url: str = "redis://localhost:6379/1"  # Different DB for tests
    max_connections: int = 10
    socket_timeout: int = 1
    socket_connect_timeout: int = 1
    retry_on_timeout: bool = False


class TestSettings(Settings):
    """Test application settings."""
    
    environment: str = "test"
    debug: bool = True
    
    # Use test database and Redis settings
    database: TestDatabaseSettings = TestDatabaseSettings()
    redis: TestRedisSettings = TestRedisSettings()
    
    # Test API keys
    api_key_secret: str = "test-secret"
    gemini_api_key: str = "test-gemini-key"
    guvi_api_key: str = "test-guvi-key"


# Test settings instance
test_settings = TestSettings()