"""
Tests for Redis caching layer and session management.
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from typing import Dict, Any

from app.core.redis import redis_manager, cache_manager, CacheKeyBuilder
from app.core.session_manager import session_manager, SessionStatus, SessionState, SessionMetrics
from app.core.utils import hash_message


class TestRedisConnection:
    """Test Redis connection and basic operations."""
    
    @pytest.mark.asyncio
    async def test_redis_initialization(self):
        """Test Redis connection initialization."""
        # Initialize Redis (should work with test environment)
        try:
            await redis_manager.initialize()
            assert redis_manager.client is not None
            assert redis_manager.pool is not None
        except Exception as e:
            pytest.skip(f"Redis not available for testing: {e}")
    
    @pytest.mark.asyncio
    async def test_redis_health_check(self):
        """Test Redis health check functionality."""
        try:
            await redis_manager.initialize()
            health_status = await redis_manager.health_check()
            assert isinstance(health_status, bool)
        except Exception as e:
            pytest.skip(f"Redis not available for testing: {e}")


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


class TestCacheManager:
    """Test cache manager functionality."""
    
    @pytest.fixture(autouse=True)
    async def setup_redis(self):
        """Setup Redis for testing."""
        try:
            await redis_manager.initialize()
            yield
        except Exception as e:
            pytest.skip(f"Redis not available for testing: {e}")    
    @pytest.mark.asyncio
    async def test_session_state_caching(self):
        """Test session state caching operations."""
        session_id = "test-session-001"
        test_state = {
            "status": "active",
            "turn_count": 3,
            "risk_score": 0.75,
            "created_at": datetime.utcnow().isoformat()
        }
        
        # Test set operation
        success = await cache_manager.set_session_state(session_id, test_state, ttl=60)
        assert success is True
        
        # Test get operation
        retrieved_state = await cache_manager.get_session_state(session_id)
        assert retrieved_state is not None
        assert retrieved_state["status"] == "active"
        assert retrieved_state["turn_count"] == 3
        assert retrieved_state["risk_score"] == 0.75
        
        # Test delete operation
        success = await cache_manager.delete_session_state(session_id)
        assert success is True
        
        # Verify deletion
        retrieved_state = await cache_manager.get_session_state(session_id)
        assert retrieved_state is None
    
    @pytest.mark.asyncio
    async def test_risk_score_caching(self):
        """Test risk score caching operations."""
        message_content = "Hello, I need your bank details urgently!"
        message_hash = hash_message(message_content)
        
        risk_data = {
            "risk_score": 0.85,
            "confidence": 0.92,
            "method": "ml_ensemble",
            "factors": ["financial_keywords", "urgency_indicators"]
        }
        
        # Test set operation
        success = await cache_manager.set_risk_score(message_hash, risk_data, ttl=60)
        assert success is True
        
        # Test get operation
        retrieved_data = await cache_manager.get_risk_score(message_hash)
        assert retrieved_data is not None
        assert retrieved_data["risk_score"] == 0.85
        assert retrieved_data["confidence"] == 0.92
        assert retrieved_data["method"] == "ml_ensemble"
    
    @pytest.mark.asyncio
    async def test_entity_validation_caching(self):
        """Test entity validation caching operations."""
        entity_type = "upi"
        entity_value = "test@paytm"
        
        # Test set operation
        success = await cache_manager.set_entity_validation(entity_type, entity_value, True, ttl=60)
        assert success is True
        
        # Test get operation
        is_valid = await cache_manager.get_entity_validation(entity_type, entity_value)
        assert is_valid is True
        
        # Test with invalid entity
        success = await cache_manager.set_entity_validation(entity_type, "invalid-upi", False, ttl=60)
        assert success is True
        
        is_valid = await cache_manager.get_entity_validation(entity_type, "invalid-upi")
        assert is_valid is False
    
    @pytest.mark.asyncio
    async def test_conversation_context_caching(self):
        """Test conversation context caching operations."""
        session_id = "test-session-002"
        context = "User is asking about bank transfers and showing urgency patterns."
        
        # Test set operation
        success = await cache_manager.set_conversation_context(session_id, context, ttl=60)
        assert success is True
        
        # Test get operation
        retrieved_context = await cache_manager.get_conversation_context(session_id)
        assert retrieved_context == context


class TestSessionManager:
    """Test session manager functionality."""
    
    @pytest.fixture(autouse=True)
    async def setup_redis(self):
        """Setup Redis for testing."""
        try:
            await redis_manager.initialize()
        except Exception as e:
            pytest.skip(f"Redis not available for testing: {e}")
    
    @pytest.mark.asyncio
    async def test_session_creation(self):
        """Test session creation and retrieval."""
        session_id = "test-session-create-001"
        metadata = {"source": "test", "ip": "127.0.0.1"}
        
        # Create session
        session_state = await session_manager.create_session(session_id, metadata)
        
        assert session_state.session_id == session_id
        assert session_state.status == SessionStatus.ACTIVE
        assert session_state.metadata == metadata
        assert session_state.metrics.total_turns == 0
        assert session_state.conversation_history == []
        
        # Retrieve session
        retrieved_session = await session_manager.get_session(session_id)
        assert retrieved_session is not None
        assert retrieved_session.session_id == session_id
        assert retrieved_session.status == SessionStatus.ACTIVE
        
        # Cleanup
        await session_manager.delete_session(session_id)
    
    @pytest.mark.asyncio
    async def test_session_message_handling(self):
        """Test adding messages to session."""
        session_id = "test-session-messages-001"
        
        # Create session
        await session_manager.create_session(session_id)
        
        # Add user message
        success = await session_manager.add_message(
            session_id, "user", "Hello, I need help with payment", {"timestamp": datetime.utcnow().isoformat()}
        )
        assert success is True
        
        # Add assistant message
        success = await session_manager.add_message(
            session_id, "assistant", "I can help you with that", {"timestamp": datetime.utcnow().isoformat()}
        )
        assert success is True
        
        # Retrieve session and check messages
        session_state = await session_manager.get_session(session_id)
        assert session_state is not None
        assert len(session_state.conversation_history) == 2
        assert session_state.metrics.total_turns == 1  # Only user messages count as turns
        
        # Check message content
        assert session_state.conversation_history[0]["role"] == "user"
        assert session_state.conversation_history[0]["content"] == "Hello, I need help with payment"
        assert session_state.conversation_history[1]["role"] == "assistant"
        
        # Cleanup
        await session_manager.delete_session(session_id)
    
    @pytest.mark.asyncio
    async def test_session_risk_assessment(self):
        """Test adding risk assessments to session."""
        session_id = "test-session-risk-001"
        
        # Create session
        await session_manager.create_session(session_id)
        
        # Add risk assessment
        success = await session_manager.add_risk_assessment(
            session_id, 0.85, 0.92, "ml_ensemble", {"financial_keywords": True, "urgency": True}
        )
        assert success is True
        
        # Retrieve session and check risk assessment
        session_state = await session_manager.get_session(session_id)
        assert session_state is not None
        assert len(session_state.risk_assessments) == 1
        assert session_state.metrics.risk_score == 0.85
        assert session_state.metrics.confidence_level == 0.92
        
        risk_assessment = session_state.risk_assessments[0]
        assert risk_assessment["risk_score"] == 0.85
        assert risk_assessment["confidence"] == 0.92
        assert risk_assessment["method"] == "ml_ensemble"
        
        # Cleanup
        await session_manager.delete_session(session_id)
    
    @pytest.mark.asyncio
    async def test_session_entity_extraction(self):
        """Test adding extracted entities to session."""
        session_id = "test-session-entities-001"
        
        # Create session
        await session_manager.create_session(session_id)
        
        # Add extracted entity
        success = await session_manager.add_extracted_entity(
            session_id, "upi", "test@paytm", 0.95, "Found in message: 'Send money to test@paytm'"
        )
        assert success is True
        
        # Retrieve session and check entity
        session_state = await session_manager.get_session(session_id)
        assert session_state is not None
        assert len(session_state.extracted_entities) == 1
        
        entity = session_state.extracted_entities[0]
        assert entity["entity_type"] == "upi"
        assert entity["entity_value"] == "test@paytm"
        assert entity["confidence"] == 0.95
        assert "test@paytm" in entity["context"]
        
        # Cleanup
        await session_manager.delete_session(session_id)
    
    @pytest.mark.asyncio
    async def test_session_agent_activation(self):
        """Test agent activation for session."""
        session_id = "test-session-agent-001"
        
        # Create session
        await session_manager.create_session(session_id)
        
        # Activate agent
        success = await session_manager.activate_agent(session_id, "digitally_naive")
        assert success is True
        
        # Retrieve session and check activation
        session_state = await session_manager.get_session(session_id)
        assert session_state is not None
        assert session_state.metrics.agent_activated is True
        assert session_state.metrics.persona_type == "digitally_naive"
        
        # Cleanup
        await session_manager.delete_session(session_id)
    
    @pytest.mark.asyncio
    async def test_session_completion(self):
        """Test session completion."""
        session_id = "test-session-complete-001"
        
        # Create session
        session_state = await session_manager.create_session(session_id)
        original_start_time = session_state.metrics.start_time
        
        # Wait a moment to ensure duration calculation
        await asyncio.sleep(0.1)
        
        # Complete session
        success = await session_manager.complete_session(session_id)
        assert success is True
        
        # Retrieve session and check completion
        session_state = await session_manager.get_session(session_id)
        assert session_state is not None
        assert session_state.status == SessionStatus.COMPLETED
        assert session_state.metrics.engagement_duration > 0
        
        # Cleanup
        await session_manager.delete_session(session_id)
    
    @pytest.mark.asyncio
    async def test_session_cleanup(self):
        """Test session cleanup functionality."""
        # Create multiple test sessions
        session_ids = ["cleanup-001", "cleanup-002", "cleanup-003"]
        
        for session_id in session_ids:
            await session_manager.create_session(session_id)
        
        # Complete some sessions
        await session_manager.complete_session("cleanup-001")
        await session_manager.expire_session("cleanup-002")
        
        # Run cleanup (with very short max age to clean up all sessions)
        cleaned_count = await session_manager.cleanup_expired_sessions(max_age_hours=0)
        
        # Should have cleaned up at least the completed and expired sessions
        assert cleaned_count >= 2
        
        # Verify sessions are cleaned up
        session_001 = await session_manager.get_session("cleanup-001")
        session_002 = await session_manager.get_session("cleanup-002")
        
        # These should be None (cleaned up)
        assert session_001 is None
        assert session_002 is None
        
        # Cleanup remaining session
        await session_manager.delete_session("cleanup-003")


if __name__ == "__main__":
    pytest.main([__file__])