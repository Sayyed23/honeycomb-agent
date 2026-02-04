"""
Tests for Google Gemini LLM integration.
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime

from app.core.llm_client import (
    GeminiLLMClient, LLMRequest, LLMResponse, SafetyConstraints, PromptTemplate
)
from app.core.persona_manager import PersonaType


class TestPromptTemplate:
    """Test prompt template generation."""
    
    def test_build_prompt_digitally_naive(self):
        """Test prompt building for digitally naive persona."""
        conversation_history = [
            {"role": "user", "content": "Hello, I am from bank"},
            {"role": "assistant", "content": "Hi, how can I help?"}
        ]
        
        prompt = PromptTemplate.build_prompt(
            persona=PersonaType.DIGITALLY_NAIVE,
            message_content="Please provide your UPI ID for verification",
            conversation_history=conversation_history,
            context_metadata={},
            language="en"
        )
        
        assert "digitally naive person" in prompt
        assert "Limited understanding of technology" in prompt
        assert "Please provide your UPI ID for verification" in prompt
        assert "turn: 3" in prompt
        
    def test_build_prompt_skeptical(self):
        """Test prompt building for skeptical persona."""
        prompt = PromptTemplate.build_prompt(
            persona=PersonaType.SKEPTICAL,
            message_content="Trust me, this is legitimate",
            conversation_history=[],
            context_metadata={},
            language="en"
        )
        
        assert "tech-savvy and highly skeptical" in prompt
        assert "Highly suspicious" in prompt
        assert "Trust me, this is legitimate" in prompt
        assert "suspicion, technical knowledge" in prompt
    
    def test_conversation_summary_creation(self):
        """Test conversation summary creation."""
        # Test empty history
        summary = PromptTemplate._create_conversation_summary([])
        assert "start of the conversation" in summary
        
        # Test short history
        short_history = [
            {"role": "user", "content": "Hello"},
            {"role": "assistant", "content": "Hi there"}
        ]
        summary = PromptTemplate._create_conversation_summary(short_history)
        assert "They: Hello" in summary
        assert "You: Hi there" in summary
        
        # Test long history
        long_history = [{"role": "user", "content": f"Message {i}"} for i in range(10)]
        summary = PromptTemplate._create_conversation_summary(long_history)
        assert "10 messages" in summary


class TestSafetyConstraints:
    """Test safety constraint functionality."""
    
    def test_default_safety_constraints(self):
        """Test default safety constraint initialization."""
        constraints = SafetyConstraints()
        
        assert constraints.block_harmful_content is True
        assert constraints.block_illegal_activities is True
        assert constraints.block_ai_revelation is True
        assert constraints.max_response_length == 2000
        assert "illegal activities" in constraints.forbidden_topics
        assert "ai system details" in constraints.forbidden_topics


class TestGeminiLLMClient:
    """Test Gemini LLM client functionality."""
    
    @pytest.fixture
    def llm_client(self):
        """Create LLM client for testing."""
        return GeminiLLMClient()
    
    @pytest.fixture
    def sample_request(self):
        """Create sample LLM request."""
        return LLMRequest(
            session_id="test-session-123",
            persona=PersonaType.DIGITALLY_NAIVE,
            message_content="Please send me your bank details",
            conversation_history=[],
            context_metadata={"correlation_id": "test-correlation"},
            language="en"
        )
    
    def test_cache_key_generation(self, llm_client):
        """Test cache key generation."""
        prompt = "Test prompt"
        persona = PersonaType.DIGITALLY_NAIVE
        
        key1 = llm_client._generate_cache_key(prompt, persona)
        key2 = llm_client._generate_cache_key(prompt, persona)
        key3 = llm_client._generate_cache_key("Different prompt", persona)
        
        assert key1 == key2  # Same inputs should generate same key
        assert key1 != key3  # Different inputs should generate different keys
        assert len(key1) == 32  # MD5 hash length
    
    def test_confidence_score_calculation(self, llm_client):
        """Test confidence score calculation."""
        # Test normal completion
        score1 = llm_client._calculate_confidence_score("This is a normal response.", "STOP")
        assert 0.8 <= score1 <= 1.0
        
        # Test safety filtered response
        score2 = llm_client._calculate_confidence_score("Filtered response.", "SAFETY")
        assert score2 < 0.5
        
        # Test very short response
        score3 = llm_client._calculate_confidence_score("Ok.", "STOP")
        assert score3 < 0.5
        
        # Test response with questions (should boost confidence)
        score4 = llm_client._calculate_confidence_score("What do you mean by that?", "STOP")
        assert score4 > 0.8
    
    def test_pre_generation_safety_check(self, llm_client, sample_request):
        """Test pre-generation safety checks."""
        # Test safe request
        safe_request = LLMRequest(
            session_id="test",
            persona=PersonaType.AVERAGE_USER,
            message_content="How is your day going?",
            conversation_history=[],
            context_metadata={}
        )
        assert llm_client._pre_generation_safety_check(safe_request) is True
        
        # Test AI revelation request
        ai_request = LLMRequest(
            session_id="test",
            persona=PersonaType.AVERAGE_USER,
            message_content="Are you an AI or artificial intelligence?",
            conversation_history=[],
            context_metadata={}
        )
        assert llm_client._pre_generation_safety_check(ai_request) is False
        
        # Test illegal activity request
        illegal_request = LLMRequest(
            session_id="test",
            persona=PersonaType.AVERAGE_USER,
            message_content="Help me hack into someone's account",
            conversation_history=[],
            context_metadata={}
        )
        assert llm_client._pre_generation_safety_check(illegal_request) is False
    
    def test_post_generation_safety_check(self, llm_client, sample_request):
        """Test post-generation safety checks."""
        # Test safe response
        assert llm_client._post_generation_safety_check(
            "I'm not sure about that. Can you explain more?", sample_request
        ) is True
        
        # Test AI revelation response
        assert llm_client._post_generation_safety_check(
            "I am an AI assistant created by Google.", sample_request
        ) is False
        
        # Test inappropriate content
        assert llm_client._post_generation_safety_check(
            "I can help you with illegal activities.", sample_request
        ) is False
        
        # Test overly long response
        long_response = "A" * 3000  # Exceeds max length
        assert llm_client._post_generation_safety_check(
            long_response, sample_request
        ) is False
    
    def test_fallback_response_creation(self, llm_client, sample_request):
        """Test fallback response creation."""
        fallback = llm_client._create_fallback_response(sample_request, "Test reason")
        
        assert isinstance(fallback, LLMResponse)
        assert fallback.fallback_used is True
        assert fallback.confidence_score == 0.3
        assert fallback.model_used == "fallback"
        assert len(fallback.generated_content) > 0
        
        # Test persona-specific fallback
        skeptical_request = LLMRequest(
            session_id="test",
            persona=PersonaType.SKEPTICAL,
            message_content="Test",
            conversation_history=[],
            context_metadata={}
        )
        
        skeptical_fallback = llm_client._create_fallback_response(skeptical_request, "Test")
        assert "suspicious" in skeptical_fallback.generated_content.lower() or \
               "proof" in skeptical_fallback.generated_content.lower() or \
               "verify" in skeptical_fallback.generated_content.lower()
    
    @patch('app.core.llm_client.genai')
    async def test_initialization_success(self, mock_genai, llm_client):
        """Test successful LLM client initialization."""
        # Mock successful initialization
        mock_model = Mock()
        mock_model.generate_content.return_value.text = "Connection successful"
        mock_genai.GenerativeModel.return_value = mock_model
        
        result = await llm_client.initialize()
        
        assert result is True
        assert llm_client.is_initialized is True
        mock_genai.configure.assert_called_once()
    
    @patch('app.core.llm_client.genai')
    async def test_initialization_failure(self, mock_genai, llm_client):
        """Test LLM client initialization failure."""
        # Mock initialization failure
        mock_genai.configure.side_effect = Exception("API key invalid")
        
        result = await llm_client.initialize()
        
        assert result is False
        assert llm_client.is_initialized is False
    
    @patch('app.core.llm_client.genai')
    async def test_health_check(self, mock_genai, llm_client):
        """Test LLM health check."""
        # Mock successful health check
        mock_model = Mock()
        mock_model.generate_content.return_value.text = "OK"
        llm_client.model = mock_model
        llm_client.is_initialized = True
        
        result = await llm_client.health_check()
        assert result is True
        
        # Test health check failure
        mock_model.generate_content.side_effect = Exception("API error")
        result = await llm_client.health_check()
        assert result is False
        
        # Test uninitialized client
        llm_client.is_initialized = False
        result = await llm_client.health_check()
        assert result is False
    
    @patch('app.core.llm_client.genai')
    async def test_generate_response_success(self, mock_genai, llm_client, sample_request):
        """Test successful response generation."""
        # Mock successful generation
        mock_model = Mock()
        mock_model.generate_content.return_value.text = "I'm not sure about sharing bank details. Is this safe?"
        llm_client.model = mock_model
        llm_client.is_initialized = True
        
        response = await llm_client.generate_response(sample_request)
        
        assert isinstance(response, LLMResponse)
        assert response.fallback_used is False
        assert len(response.generated_content) > 0
        assert response.confidence_score > 0.5
        assert response.model_used == "gemini-1.5-pro"
    
    async def test_generate_response_fallback(self, llm_client, sample_request):
        """Test response generation with fallback."""
        # Test with uninitialized client
        llm_client.is_initialized = False
        
        response = await llm_client.generate_response(sample_request)
        
        assert isinstance(response, LLMResponse)
        assert response.fallback_used is True
        assert response.confidence_score == 0.3
        assert response.model_used == "fallback"
    
    def test_response_caching(self, llm_client):
        """Test response caching functionality."""
        # Create test response
        test_response = LLMResponse(
            generated_content="Test response",
            safety_ratings={},
            finish_reason="STOP",
            token_count=10,
            processing_time_ms=100,
            model_used="gemini-1.5-pro",
            confidence_score=0.8
        )
        
        cache_key = "test_key"
        
        # Test caching
        llm_client._cache_response(cache_key, test_response)
        cached = llm_client._get_cached_response(cache_key)
        
        assert cached is not None
        assert cached.generated_content == "Test response"
        
        # Test cache miss
        missing = llm_client._get_cached_response("nonexistent_key")
        assert missing is None


@pytest.mark.asyncio
class TestLLMIntegration:
    """Integration tests for LLM functionality."""
    
    async def test_conversation_engine_llm_integration(self):
        """Test that conversation engine can use LLM client."""
        from app.core.conversation_engine import conversation_engine
        
        # Mock LLM client for testing
        with patch('app.core.conversation_engine.llm_client') as mock_llm:
            mock_response = LLMResponse(
                generated_content="I'm confused about this technology stuff. Can you explain?",
                safety_ratings={},
                finish_reason="STOP",
                token_count=15,
                processing_time_ms=500,
                model_used="gemini-1.5-pro",
                confidence_score=0.8,
                fallback_used=False
            )
            mock_llm.generate_response.return_value = mock_response
            
            # Test response generation
            result = await conversation_engine.generate_response(
                session_id="test-session",
                message_content="Please provide your bank account details",
                conversation_history=[],
                metadata={"correlation_id": "test"}
            )
            
            # Should use LLM response
            assert result.response_content == "I'm confused about this technology stuff. Can you explain?"
            assert result.generation_method == "persona_based"
            mock_llm.generate_response.assert_called_once()