"""
Tests for authentication and API key management.
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import Mock, patch
from fastapi import HTTPException, Request
from sqlalchemy.orm import Session

from app.core.auth import APIKeyManager, RateLimiter, validate_api_key_dependency
from app.database.models import APIKey, APIKeyUsage
from config.settings import settings


class TestAPIKeyManager:
    """Test cases for APIKeyManager."""
    
    def test_generate_api_key(self):
        """Test API key generation."""
        key1 = APIKeyManager.generate_api_key()
        key2 = APIKeyManager.generate_api_key()
        
        # Keys should be different
        assert key1 != key2
        
        # Keys should be reasonable length
        assert len(key1) >= 32
        assert len(key2) >= 32
        
        # Keys should be URL-safe
        import string
        allowed_chars = string.ascii_letters + string.digits + '-_'
        assert all(c in allowed_chars for c in key1)
        assert all(c in allowed_chars for c in key2)
    
    def test_hash_api_key(self):
        """Test API key hashing."""
        api_key = "test-api-key-12345"
        
        hash1 = APIKeyManager.hash_api_key(api_key)
        hash2 = APIKeyManager.hash_api_key(api_key)
        
        # Same key should produce same hash
        assert hash1 == hash2
        
        # Hash should be bytes
        assert isinstance(hash1, bytes)
        
        # Hash should be reasonable length
        assert len(hash1) == 32  # SHA-256 produces 32 bytes
    
    def test_verify_api_key(self):
        """Test API key verification."""
        api_key = "test-api-key-12345"
        key_hash = APIKeyManager.hash_api_key(api_key)
        
        # Correct key should verify
        assert APIKeyManager.verify_api_key(api_key, key_hash) is True
        
        # Wrong key should not verify
        assert APIKeyManager.verify_api_key("wrong-key", key_hash) is False
        
        # Empty key should not verify
        assert APIKeyManager.verify_api_key("", key_hash) is False
    
    def test_get_key_prefix(self):
        """Test key prefix extraction."""
        # Normal key
        key = "abcd1234-rest-of-key"
        prefix = APIKeyManager.get_key_prefix(key)
        assert prefix == "abcd1234"
        
        # Short key
        short_key = "abc"
        short_prefix = APIKeyManager.get_key_prefix(short_key)
        assert short_prefix == "abc"
        
        # Empty key
        empty_prefix = APIKeyManager.get_key_prefix("")
        assert empty_prefix == ""
    
    @pytest.mark.asyncio
    async def test_create_api_key(self):
        """Test API key creation."""
        # Mock database session
        mock_db = Mock(spec=Session)
        mock_db.add = Mock()
        mock_db.commit = Mock()
        mock_db.refresh = Mock()
        
        # Create API key
        api_key, db_key = await APIKeyManager.create_api_key(
            db=mock_db,
            key_name="Test Key",
            description="Test description",
            rate_limit_per_hour=500,
            created_by="test_user"
        )
        
        # Verify API key was generated
        assert isinstance(api_key, str)
        assert len(api_key) >= 32
        
        # Verify database record was created
        assert isinstance(db_key, APIKey)
        assert db_key.key_name == "Test Key"
        assert db_key.description == "Test description"
        assert db_key.rate_limit_per_hour == 500
        assert db_key.created_by == "test_user"
        assert db_key.key_prefix == APIKeyManager.get_key_prefix(api_key)
        
        # Verify database operations were called
        mock_db.add.assert_called_once_with(db_key)
        mock_db.commit.assert_called_once()
        mock_db.refresh.assert_called_once_with(db_key)
    
    @pytest.mark.asyncio
    async def test_validate_api_key_success(self):
        """Test successful API key validation."""
        # Create test API key
        test_key = "test-key-12345"
        key_hash = APIKeyManager.hash_api_key(test_key)
        key_prefix = APIKeyManager.get_key_prefix(test_key)
        
        # Mock database record
        mock_db_key = APIKey(
            key_name="Test Key",
            key_hash=key_hash,
            key_prefix=key_prefix,
            is_active=True,
            expires_at=None
        )
        
        # Mock database session
        mock_db = Mock(spec=Session)
        mock_query = Mock()
        mock_query.filter.return_value.all.return_value = [mock_db_key]
        mock_db.query.return_value = mock_query
        
        # Validate key
        result = await APIKeyManager.validate_api_key(mock_db, test_key)
        
        # Should return the database record
        assert result == mock_db_key
    
    @pytest.mark.asyncio
    async def test_validate_api_key_invalid(self):
        """Test API key validation with invalid key."""
        # Mock database session with no matching keys
        mock_db = Mock(spec=Session)
        mock_query = Mock()
        mock_query.filter.return_value.all.return_value = []
        mock_db.query.return_value = mock_query
        
        # Validate invalid key
        result = await APIKeyManager.validate_api_key(mock_db, "invalid-key")
        
        # Should return None
        assert result is None
    
    @pytest.mark.asyncio
    async def test_validate_api_key_expired(self):
        """Test API key validation with expired key."""
        # Create test API key
        test_key = "test-key-12345"
        key_hash = APIKeyManager.hash_api_key(test_key)
        key_prefix = APIKeyManager.get_key_prefix(test_key)
        
        # Mock expired database record
        mock_db_key = APIKey(
            key_name="Test Key",
            key_hash=key_hash,
            key_prefix=key_prefix,
            is_active=True,
            expires_at=datetime.utcnow() - timedelta(days=1)  # Expired yesterday
        )
        
        # Mock database session
        mock_db = Mock(spec=Session)
        mock_query = Mock()
        mock_query.filter.return_value.all.return_value = [mock_db_key]
        mock_db.query.return_value = mock_query
        
        # Validate expired key
        result = await APIKeyManager.validate_api_key(mock_db, test_key)
        
        # Should return None for expired key
        assert result is None
    
    @pytest.mark.asyncio
    async def test_check_rate_limit_within_limit(self):
        """Test rate limit check when within limit."""
        # Mock API key record
        mock_api_key = APIKey(
            rate_limit_per_hour=1000,
            current_hour_usage=500,
            current_hour_start=datetime.utcnow().replace(minute=0, second=0, microsecond=0)
        )
        
        mock_db = Mock(spec=Session)
        
        # Check rate limit
        result = await APIKeyManager.check_rate_limit(mock_db, mock_api_key)
        
        # Should be within limit
        assert result is True
    
    @pytest.mark.asyncio
    async def test_check_rate_limit_exceeded(self):
        """Test rate limit check when limit exceeded."""
        # Mock API key record at limit
        mock_api_key = APIKey(
            rate_limit_per_hour=1000,
            current_hour_usage=1000,
            current_hour_start=datetime.utcnow().replace(minute=0, second=0, microsecond=0)
        )
        
        mock_db = Mock(spec=Session)
        
        # Check rate limit
        result = await APIKeyManager.check_rate_limit(mock_db, mock_api_key)
        
        # Should exceed limit
        assert result is False
    
    @pytest.mark.asyncio
    async def test_check_rate_limit_new_hour(self):
        """Test rate limit reset for new hour."""
        # Mock API key record from previous hour
        mock_api_key = APIKey(
            rate_limit_per_hour=1000,
            current_hour_usage=1000,  # Was at limit
            current_hour_start=datetime.utcnow().replace(minute=0, second=0, microsecond=0) - timedelta(hours=1)
        )
        
        mock_db = Mock(spec=Session)
        
        # Check rate limit
        result = await APIKeyManager.check_rate_limit(mock_db, mock_api_key)
        
        # Should reset and be within limit
        assert result is True
        assert mock_api_key.current_hour_usage == 0
    
    @pytest.mark.asyncio
    async def test_record_api_usage(self):
        """Test API usage recording."""
        # Mock API key record
        mock_api_key = APIKey(
            id="test-id",
            usage_count=100,
            current_hour_usage=50
        )
        
        # Mock request
        mock_request = Mock(spec=Request)
        mock_request.url.path = "/api/test"
        mock_request.method = "POST"
        mock_request.client.host = "127.0.0.1"
        mock_request.headers.get.return_value = "test-agent"
        
        # Mock database session
        mock_db = Mock(spec=Session)
        mock_db.add = Mock()
        mock_db.commit = Mock()
        
        # Record usage
        await APIKeyManager.record_api_usage(
            db=mock_db,
            api_key_record=mock_api_key,
            request=mock_request,
            status_code=200,
            response_time_ms=150
        )
        
        # Verify counters were updated
        assert mock_api_key.usage_count == 101
        assert mock_api_key.current_hour_usage == 51
        assert mock_api_key.last_used is not None
        
        # Verify usage record was created
        mock_db.add.assert_called_once()
        mock_db.commit.assert_called_once()


class TestRateLimiter:
    """Test cases for RateLimiter."""
    
    def test_get_rate_limit_headers(self):
        """Test rate limit header generation."""
        # Mock API key record
        mock_api_key = APIKey(
            rate_limit_per_hour=1000,
            current_hour_usage=250,
            current_hour_start=datetime.utcnow().replace(minute=0, second=0, microsecond=0)
        )
        
        # Get headers
        headers = RateLimiter.get_rate_limit_headers(mock_api_key)
        
        # Verify headers
        assert headers["X-RateLimit-Limit"] == "1000"
        assert headers["X-RateLimit-Remaining"] == "750"
        assert "X-RateLimit-Reset" in headers
        
        # Reset time should be a valid timestamp
        reset_time = int(headers["X-RateLimit-Reset"])
        assert reset_time > 0


class TestValidateAPIKeyDependency:
    """Test cases for the FastAPI dependency."""
    
    @pytest.mark.asyncio
    async def test_missing_api_key(self):
        """Test request without API key."""
        # Mock request without API key
        mock_request = Mock(spec=Request)
        mock_request.headers.get.return_value = None
        mock_request.client.host = "127.0.0.1"
        mock_request.url = "http://test.com/api/test"
        
        mock_db = Mock(spec=Session)
        
        # Should raise 401 exception
        with pytest.raises(HTTPException) as exc_info:
            await validate_api_key_dependency(mock_request, mock_db)
        
        assert exc_info.value.status_code == 401
        assert "Missing x-api-key header" in str(exc_info.value.detail)
    
    @pytest.mark.asyncio
    async def test_invalid_api_key(self):
        """Test request with invalid API key."""
        # Mock request with invalid API key
        mock_request = Mock(spec=Request)
        mock_request.headers.get.return_value = "invalid-key"
        mock_request.client.host = "127.0.0.1"
        mock_request.url = "http://test.com/api/test"
        
        # Mock database session with no matching keys
        mock_db = Mock(spec=Session)
        mock_query = Mock()
        mock_query.filter.return_value.all.return_value = []
        mock_db.query.return_value = mock_query
        
        # Should raise 403 exception
        with pytest.raises(HTTPException) as exc_info:
            await validate_api_key_dependency(mock_request, mock_db)
        
        assert exc_info.value.status_code == 403
        assert "Invalid or expired API key" in str(exc_info.value.detail)
    
    @pytest.mark.asyncio
    async def test_rate_limit_exceeded(self):
        """Test request that exceeds rate limit."""
        # Create test API key
        test_key = "test-key-12345"
        key_hash = APIKeyManager.hash_api_key(test_key)
        key_prefix = APIKeyManager.get_key_prefix(test_key)
        
        # Mock API key record at rate limit
        mock_db_key = APIKey(
            key_name="Test Key",
            key_hash=key_hash,
            key_prefix=key_prefix,
            is_active=True,
            expires_at=None,
            rate_limit_per_hour=1000,
            current_hour_usage=1000,
            current_hour_start=datetime.utcnow().replace(minute=0, second=0, microsecond=0)
        )
        
        # Mock request
        mock_request = Mock(spec=Request)
        mock_request.headers.get.return_value = test_key
        mock_request.client.host = "127.0.0.1"
        mock_request.url = "http://test.com/api/test"
        
        # Mock database session
        mock_db = Mock(spec=Session)
        mock_query = Mock()
        mock_query.filter.return_value.all.return_value = [mock_db_key]
        mock_db.query.return_value = mock_query
        
        # Should raise 429 exception
        with pytest.raises(HTTPException) as exc_info:
            await validate_api_key_dependency(mock_request, mock_db)
        
        assert exc_info.value.status_code == 429
        assert "Rate limit exceeded" in str(exc_info.value.detail)
        
        # Should include rate limit headers
        assert "X-RateLimit-Limit" in exc_info.value.headers
        assert "X-RateLimit-Remaining" in exc_info.value.headers
        assert "X-RateLimit-Reset" in exc_info.value.headers
    
    @pytest.mark.asyncio
    async def test_valid_api_key(self):
        """Test request with valid API key."""
        # Create test API key
        test_key = "test-key-12345"
        key_hash = APIKeyManager.hash_api_key(test_key)
        key_prefix = APIKeyManager.get_key_prefix(test_key)
        
        # Mock valid API key record
        mock_db_key = APIKey(
            key_name="Test Key",
            key_hash=key_hash,
            key_prefix=key_prefix,
            is_active=True,
            expires_at=None,
            rate_limit_per_hour=1000,
            current_hour_usage=500,
            current_hour_start=datetime.utcnow().replace(minute=0, second=0, microsecond=0)
        )
        
        # Mock request
        mock_request = Mock(spec=Request)
        mock_request.headers.get.return_value = test_key
        mock_request.client.host = "127.0.0.1"
        mock_request.url = "http://test.com/api/test"
        
        # Mock database session
        mock_db = Mock(spec=Session)
        mock_query = Mock()
        mock_query.filter.return_value.all.return_value = [mock_db_key]
        mock_db.query.return_value = mock_query
        
        # Should return the API key record
        result = await validate_api_key_dependency(mock_request, mock_db)
        
        assert result == mock_db_key