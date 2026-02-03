"""
Pytest configuration and fixtures for testing.
"""

import pytest
import os
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Set test environment before importing app modules
os.environ["ENVIRONMENT"] = "test"
os.environ["DATABASE_URL"] = "sqlite:///./test.db"
os.environ["REDIS_URL"] = "redis://localhost:6379/1"

from config.test_settings import test_settings
from app.database.models import Base
from app.database.connection import get_db
from app.main import app


@pytest.fixture(scope="session")
def test_engine():
    """Create test database engine."""
    engine = create_engine(
        test_settings.database.url,
        echo=test_settings.database.echo,
        connect_args={"check_same_thread": False}  # SQLite specific
    )
    
    # Create all tables
    Base.metadata.create_all(bind=engine)
    
    yield engine
    
    # Clean up
    Base.metadata.drop_all(bind=engine)
    
    # Remove test database file
    db_file = Path("./test.db")
    if db_file.exists():
        db_file.unlink()


@pytest.fixture(scope="function")
def test_db(test_engine):
    """Create test database session."""
    TestingSessionLocal = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=test_engine
    )
    
    session = TestingSessionLocal()
    
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture(scope="function")
def client(test_db):
    """Create test client with database dependency override."""
    
    def override_get_db():
        try:
            yield test_db
        finally:
            pass
    
    app.dependency_overrides[get_db] = override_get_db
    
    with TestClient(app) as test_client:
        yield test_client
    
    # Clean up
    app.dependency_overrides.clear()


@pytest.fixture(scope="function")
def mock_redis():
    """Mock Redis for testing."""
    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value=None)
    mock_redis.set = AsyncMock(return_value=True)
    mock_redis.delete = AsyncMock(return_value=1)
    mock_redis.exists = AsyncMock(return_value=False)
    mock_redis.ping = AsyncMock(return_value=True)
    return mock_redis


@pytest.fixture(scope="function")
def sample_api_key(test_db):
    """Create a sample API key for testing."""
    from app.database.models import APIKey
    from app.core.auth import APIKeyManager
    from datetime import datetime, timedelta
    
    # Create API key
    api_key = APIKeyManager.generate_api_key()
    key_hash = APIKeyManager.hash_api_key(api_key)
    
    api_key_record = APIKey(
        key_name="test-key",
        key_hash=key_hash,
        key_prefix=APIKeyManager.get_key_prefix(api_key),
        is_active=True,
        expires_at=datetime.utcnow() + timedelta(days=30),
        rate_limit_per_hour=1000,
        created_at=datetime.utcnow()
    )
    
    test_db.add(api_key_record)
    test_db.commit()
    test_db.refresh(api_key_record)
    
    return {
        "api_key": api_key,
        "record": api_key_record
    }


@pytest.fixture(scope="function")
def auth_headers(sample_api_key):
    """Create authentication headers for testing."""
    return {"x-api-key": sample_api_key["api_key"]}