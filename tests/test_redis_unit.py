"""
Unit tests for Redis caching layer components (without requiring Redis server).
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

from app.core.redis import CacheKeyBuilder, CacheManager, RedisConnectionManager
from app.core.session_manager import SessionManager, SessionState, SessionStatus, SessionMetrics
from app.core.utils import hash_message, sanitize_input, validate_session_id


class TestCacheKeyBuilder:
    """Test cache key building utilities."""
    
    def test_session_state_key(self):
        """Test session state key generation."""
        key = CacheKeyBuilder.session_state("test-session-123")
        assert key == "session:test-session-123:state"
    
    def test_risk_score_key(self):
        """Test risk score key generation."""
        message_hash = "abc123def456"
        key = CacheKeyBuilder.risk_score(message_hash)
        assert key == f"risk:{message_hash}:score"
    
    def test_entity_validation_key(self):
        """Test entity validation key generation."""
        key = CacheKeyBuilder.entity_validation("upi", "test@paytm")
        assert key == "entity:upi:test@paytm:valid"
    
    def test_conversation_context_key(self):
        """Test conversation context key generation."""
        key = CacheKeyBuilder.conversation_context("session-456")
        assert key == "context:session-456:summary"
    
    def test_session_lock_key(self):
        """Test session lock key generation."""
        key = CacheKeyBuilder.session_lock("session-789")
        assert key == "lock:session:session-789"


class TestUtilityFunctions:
    """Test utility functions used by Redis components."""
    
    def test_hash_message(self):
        """Test message hashing functionality."""
        message1 = "Hello, I need your bank details"
        message2 = "Hello, I need your bank details"
        message3 = "Different message content"
        
        hash1 = hash_message(message1)
        hash2 = hash_message(message2)
        hash3 = hash_message(message3)
        
        # Same messages should produce same hash
        assert hash1 == hash2
        
        # Different messages should produce different hashes
        assert hash1 != hash3
        
        # Hash should be consistent format (64 character hex string)
        assert len(hash1) == 64
        assert all(c in '0123456789abcdef' for c in hash1)
    
    def test_hash_message_with_metadata(self):
        """Test message hashing with metadata."""
        message = "Test message"
        metadata1 = {"source": "test", "timestamp": "2024-01-01T00:00:00Z"}
        metadata2 = {"source": "test", "timestamp": "2024-01-01T00:00:00Z"}
        metadata3 = {"source": "different", "timestamp": "2024-01-01T00:00:00Z"}
        
        hash1 = hash_message(message, metadata1)
        hash2 = hash_message(message, metadata2)
        hash3 = hash_message(message, metadata3)
        
        # Same message and metadata should produce same hash
        assert hash1 == hash2
        
        # Different metadata should produce different hash
        assert hash1 != hash3
    
    def test_sanitize_input(self):
        """Test input sanitization."""
        # Test normal input
        clean_text = sanitize_input("Hello world")
        assert clean_text == "Hello world"
        
        # Test input with control characters
        dirty_text = "Hello\x00\x01world\x7F"
        clean_text = sanitize_input(dirty_text)
        assert clean_text == "Helloworld"
        
        # Test input with excessive whitespace
        whitespace_text = "Hello    \n\n\n   world   \t\t"
        clean_text = sanitize_input(whitespace_text)
        assert clean_text == "Hello world"
        
        # Test length truncation
        long_text = "a" * 6000
        clean_text = sanitize_input(long_text, max_length=100)
        assert len(clean_text) == 100
    
    def test_validate_session_id(self):
        """Test session ID validation."""
        # Valid session IDs
        assert validate_session_id("session-123") is True
        assert validate_session_id("test_session_456") is True
        assert validate_session_id("abc123def456") is True
        
        # Invalid session IDs
        assert validate_session_id("") is False
        assert validate_session_id("a" * 101) is False  # Too long
        assert validate_session_id("session@123") is False  # Invalid character
        assert validate_session_id("session 123") is False  # Space not allowed
        assert validate_session_id(None) is False


class TestSessionStateDataStructure:
    """Test session state data structure and serialization."""
    
    def test_session_state_creation(self):
        """Test creating session state object."""
        now = datetime.utcnow()
        metrics = SessionMetrics(
            total_turns=3,
            start_time=now,
            last_activity=now,
            engagement_duration=120,
            risk_score=0.75,
            confidence_level=0.85,
            agent_activated=True,
            persona_type="digitally_naive"
        )
        
        session_state = SessionState(
            session_id="test-session-001",
            status=SessionStatus.ACTIVE,
            metrics=metrics,
            conversation_history=[
                {"role": "user", "content": "Hello", "timestamp": now.isoformat()},
                {"role": "assistant", "content": "Hi there", "timestamp": now.isoformat()}
            ],
            extracted_entities=[
                {"entity_type": "upi", "entity_value": "test@paytm", "confidence": 0.95}
            ],
            risk_assessments=[
                {"risk_score": 0.75, "confidence": 0.85, "method": "ml_ensemble"}
            ],
            metadata={"source": "test"},
            created_at=now,
            updated_at=now
        )
        
        assert session_state.session_id == "test-session-001"
        assert session_state.status == SessionStatus.ACTIVE
        assert session_state.metrics.total_turns == 3
        assert session_state.metrics.agent_activated is True
        assert len(session_state.conversation_history) == 2
        assert len(session_state.extracted_entities) == 1
        assert len(session_state.risk_assessments) == 1
    
    def test_session_state_serialization(self):
        """Test session state to_dict and from_dict methods."""
        now = datetime.utcnow()
        metrics = SessionMetrics(
            total_turns=2,
            start_time=now,
            last_activity=now,
            risk_score=0.65,
            confidence_level=0.80
        )
        
        original_state = SessionState(
            session_id="serialize-test",
            status=SessionStatus.ACTIVE,
            metrics=metrics,
            conversation_history=[{"role": "user", "content": "Test message"}],
            extracted_entities=[],
            risk_assessments=[],
            metadata={"test": True},
            created_at=now,
            updated_at=now
        )
        
        # Serialize to dict
        state_dict = original_state.to_dict()
        
        assert state_dict["session_id"] == "serialize-test"
        assert state_dict["status"] == "active"
        assert state_dict["metrics"]["total_turns"] == 2
        assert state_dict["metrics"]["risk_score"] == 0.65
        assert len(state_dict["conversation_history"]) == 1
        
        # Deserialize from dict
        restored_state = SessionState.from_dict(state_dict)
        
        assert restored_state.session_id == original_state.session_id
        assert restored_state.status == original_state.status
        assert restored_state.metrics.total_turns == original_state.metrics.total_turns
        assert restored_state.metrics.risk_score == original_state.metrics.risk_score
        assert len(restored_state.conversation_history) == len(original_state.conversation_history)


class TestRedisConnectionManager:
    """Test Redis connection manager (mocked)."""
    
    @pytest.mark.asyncio
    async def test_connection_manager_initialization(self):
        """Test connection manager initialization logic."""
        manager = RedisConnectionManager()
        
        # Initially should be None
        assert manager.pool is None
        assert manager.client is None
        
        # Mock the Redis components
        with patch('app.core.redis.ConnectionPool') as mock_pool_class, \
             patch('app.core.redis.redis.Redis') as mock_redis_class:
            
            mock_pool = AsyncMock()
            mock_client = AsyncMock()
            mock_pool_class.from_url.return_value = mock_pool
            mock_redis_class.return_value = mock_client
            mock_client.ping.return_value = True
            
            await manager.initialize()
            
            # Should have created pool and client
            assert manager.pool == mock_pool
            assert manager.client == mock_client
            
            # Should have called ping to test connection
            mock_client.ping.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_connection_manager_health_check(self):
        """Test connection manager health check logic."""
        manager = RedisConnectionManager()
        
        # Mock Redis client
        mock_client = AsyncMock()
        manager.client = mock_client
        
        # Test successful health check
        mock_client.ping.return_value = True
        mock_client.set.return_value = True
        mock_client.get.return_value = "test"
        mock_client.delete.return_value = 1
        
        health_status = await manager.health_check()
        assert health_status is True
        
        # Test failed health check
        mock_client.ping.side_effect = Exception("Connection failed")
        
        health_status = await manager.health_check()
        assert health_status is False


class TestCacheManagerMocked:
    """Test cache manager with mocked Redis client."""
    
    @pytest.fixture
    def mock_cache_manager(self):
        """Create cache manager with mocked Redis client."""
        cache_manager = CacheManager()
        
        # Mock the get_client method
        mock_client = AsyncMock()
        cache_manager.get_client = AsyncMock(return_value=mock_client)
        
        return cache_manager, mock_client
    
    @pytest.mark.asyncio
    async def test_session_state_caching_logic(self, mock_cache_manager):
        """Test session state caching logic without Redis."""
        cache_manager, mock_client = mock_cache_manager
        
        session_id = "test-session-001"
        test_state = {
            "status": "active",
            "turn_count": 3,
            "risk_score": 0.75
        }
        
        # Test set operation
        mock_client.set.return_value = True
        success = await cache_manager.set_session_state(session_id, test_state, ttl=60)
        
        assert success is True
        mock_client.set.assert_called_once()
        
        # Verify the key format and TTL
        call_args = mock_client.set.call_args
        assert call_args[0][0] == f"session:{session_id}:state"
        assert call_args[1]["ex"] == 60
        
        # Test get operation
        import json
        mock_client.get.return_value = json.dumps(test_state)
        retrieved_state = await cache_manager.get_session_state(session_id)
        
        assert retrieved_state is not None
        assert retrieved_state["status"] == "active"
        assert retrieved_state["turn_count"] == 3
        assert retrieved_state["risk_score"] == 0.75
    
    @pytest.mark.asyncio
    async def test_risk_score_caching_logic(self, mock_cache_manager):
        """Test risk score caching logic without Redis."""
        cache_manager, mock_client = mock_cache_manager
        
        message_hash = "abc123def456"
        risk_data = {
            "risk_score": 0.85,
            "confidence": 0.92,
            "method": "ml_ensemble"
        }
        
        # Test set operation
        mock_client.set.return_value = True
        success = await cache_manager.set_risk_score(message_hash, risk_data, ttl=3600)
        
        assert success is True
        mock_client.set.assert_called_once()
        
        # Verify the key format and TTL
        call_args = mock_client.set.call_args
        assert call_args[0][0] == f"risk:{message_hash}:score"
        assert call_args[1]["ex"] == 3600
    
    @pytest.mark.asyncio
    async def test_entity_validation_caching_logic(self, mock_cache_manager):
        """Test entity validation caching logic without Redis."""
        cache_manager, mock_client = mock_cache_manager
        
        entity_type = "upi"
        entity_value = "test@paytm"
        
        # Test set operation for valid entity
        mock_client.set.return_value = True
        success = await cache_manager.set_entity_validation(entity_type, entity_value, True, ttl=86400)
        
        assert success is True
        mock_client.set.assert_called_once()
        
        # Verify the key format and value
        call_args = mock_client.set.call_args
        assert call_args[0][0] == f"entity:{entity_type}:{entity_value}:valid"
        assert call_args[0][1] == "true"
        assert call_args[1]["ex"] == 86400
        
        # Test get operation
        mock_client.get.return_value = "true"
        is_valid = await cache_manager.get_entity_validation(entity_type, entity_value)
        
        assert is_valid is True
        
        # Test with false value
        mock_client.get.return_value = "false"
        is_valid = await cache_manager.get_entity_validation(entity_type, entity_value)
        
        assert is_valid is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])