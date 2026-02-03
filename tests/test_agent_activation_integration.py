"""
Unit tests for agent activation system integration.
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from app.core.agent_activation import (
    AgentActivationEngine, 
    PersonaType, 
    ActivationDecision,
    ContextualFactors,
    ActivationResult
)


class TestAgentActivationEngine:
    """Test cases for the AgentActivationEngine."""
    
    @pytest.fixture
    def activation_engine(self):
        """Create a fresh activation engine for testing."""
        return AgentActivationEngine()
    
    @pytest.mark.asyncio
    async def test_high_risk_activation(self, activation_engine):
        """Test that high-risk messages trigger agent activation."""
        result = await activation_engine.should_activate_agent(
            session_id='test-session-001',
            risk_score=0.85,
            confidence=0.9,
            message_content='Send money urgently via UPI',
            conversation_history=[],
            metadata={'language': 'en'}
        )
        
        # High risk should likely activate (probabilistic, so we check structure)
        assert isinstance(result, ActivationResult)
        assert result.decision in [ActivationDecision.ACTIVATE, ActivationDecision.NO_ACTIVATE]
        assert result.probability_used >= 0.75  # Should be high probability
        assert len(result.reasoning) > 0
        assert result.confidence > 0.0
        
        if result.decision == ActivationDecision.ACTIVATE:
            assert result.persona in [PersonaType.DIGITALLY_NAIVE, PersonaType.AVERAGE_USER, PersonaType.SKEPTICAL]
        else:
            assert result.response_template is not None
    
    @pytest.mark.asyncio
    async def test_low_risk_no_activation(self, activation_engine):
        """Test that low-risk messages do not trigger agent activation."""
        result = await activation_engine.should_activate_agent(
            session_id='test-session-002',
            risk_score=0.3,
            confidence=0.8,
            message_content='Hello, how are you?',
            conversation_history=[],
            metadata={'language': 'en'}
        )
        
        # Low risk should not activate
        assert result.decision == ActivationDecision.NO_ACTIVATE
        assert result.persona is None
        assert result.response_template is not None
        assert 'risk_score_below_threshold' in result.reasoning[0]
    
    @pytest.mark.asyncio
    async def test_persona_selection_logic(self, activation_engine):
        """Test persona selection based on message characteristics."""
        # Test technical/financial message -> skeptical persona
        with patch('random.random', return_value=0.1):  # Force activation
            result = await activation_engine.should_activate_agent(
                session_id='test-session-003',
                risk_score=0.85,
                confidence=0.9,
                message_content='UPI technical issue with crypto investment',
                conversation_history=[],
                metadata={'language': 'en'}
            )
            
            if result.decision == ActivationDecision.ACTIVATE:
                # Should select skeptical for technical/financial complexity
                assert result.persona == PersonaType.SKEPTICAL
    
    @pytest.mark.asyncio
    async def test_contextual_adjustments(self, activation_engine):
        """Test that contextual factors adjust activation probability."""
        # Mock session manager to return session with previous engagement
        mock_session_state = MagicMock()
        mock_session_state.metrics.agent_activated = True
        mock_session_state.metrics.total_turns = 5
        mock_session_state.metrics.start_time = None
        mock_session_state.metrics.last_activity = None
        
        with patch('app.core.agent_activation.session_manager.get_session', 
                  return_value=mock_session_state):
            result = await activation_engine.should_activate_agent(
                session_id='test-session-004',
                risk_score=0.85,
                confidence=0.9,
                message_content='Send money urgently',
                conversation_history=[],
                metadata={'language': 'en'}
            )
            
            # Should have contextual adjustments that reduce probability
            assert 'previous_engagements' in result.contextual_adjustments
            assert result.contextual_adjustments['previous_engagements'] < 0
    
    @pytest.mark.asyncio
    async def test_multilingual_responses(self, activation_engine):
        """Test that non-engaging responses are generated in different languages."""
        # Test Hindi response
        result = await activation_engine.should_activate_agent(
            session_id='test-session-005',
            risk_score=0.3,
            confidence=0.8,
            message_content='नमस्ते',
            conversation_history=[],
            metadata={'language': 'hi'}
        )
        
        assert result.decision == ActivationDecision.NO_ACTIVATE
        assert result.response_template is not None
        # Should contain Hindi text (basic check)
        assert any(ord(char) > 127 for char in result.response_template)  # Non-ASCII characters
    
    @pytest.mark.asyncio
    async def test_probability_bounds(self, activation_engine):
        """Test that activation probabilities stay within expected bounds."""
        # Test multiple scenarios to ensure probabilities are reasonable
        test_cases = [
            (0.75, 0.8),  # Minimum threshold
            (0.85, 0.9),  # High risk
            (0.95, 0.95), # Maximum risk
        ]
        
        for risk_score, confidence in test_cases:
            result = await activation_engine.should_activate_agent(
                session_id=f'test-session-{risk_score}',
                risk_score=risk_score,
                confidence=confidence,
                message_content='Test message',
                conversation_history=[],
                metadata={'language': 'en'}
            )
            
            # Probability should be within expected bounds
            assert 0.75 <= result.probability_used <= 0.95
    
    def test_activation_statistics(self, activation_engine):
        """Test activation statistics tracking."""
        # Initial stats should be empty
        stats = activation_engine.get_activation_statistics()
        assert stats['total_decisions'] == 0
        assert stats['total_activations'] == 0
        assert stats['activation_rate'] == 0.0
        assert stats['target_rate_range'] == '80-95%'
        
        # Update stats manually to test
        activation_engine._update_activation_stats(True)
        activation_engine._update_activation_stats(False)
        activation_engine._update_activation_stats(True)
        
        updated_stats = activation_engine.get_activation_statistics()
        assert updated_stats['total_decisions'] == 3
        assert updated_stats['total_activations'] == 2
        assert updated_stats['activation_rate'] == 2/3
    
    def test_base_probability_calculation(self, activation_engine):
        """Test base probability calculation for different risk scores."""
        # Test different risk score ranges
        test_cases = [
            (0.75, 0.8, 0.80),  # Should be around 0.80
            (0.85, 0.9, 0.90),  # Should be around 0.90
            (0.95, 0.95, 0.95), # Should be around 0.95
        ]
        
        for risk_score, confidence, expected_base in test_cases:
            base_prob = activation_engine._calculate_base_probability(risk_score, confidence)
            # Allow some variance due to confidence adjustments
            assert abs(base_prob - expected_base) <= 0.1
    
    @pytest.mark.asyncio
    async def test_persona_integration(self, activation_engine):
        """Test integration with persona manager during activation."""
        # Test that persona is selected when agent is activated
        result = await activation_engine.should_activate_agent(
            session_id='test-persona-integration',
            risk_score=0.85,
            confidence=0.9,
            message_content='I am bank officer, send UPI details urgently',
            conversation_history=[],
            metadata={'language': 'en'}
        )
        
        # If activated, should have a persona selected
        if result.decision == ActivationDecision.ACTIVATE:
            assert result.persona is not None
            assert isinstance(result.persona, PersonaType)
        else:
            # If not activated, persona should be None
            assert result.persona is None
    
    @pytest.mark.asyncio
    async def test_error_handling(self, activation_engine):
        """Test error handling in activation decision process."""
        # Test with invalid session manager
        with patch('app.core.agent_activation.session_manager.get_session', 
                  side_effect=Exception("Redis error")):
            result = await activation_engine.should_activate_agent(
                session_id='test-session-error',
                risk_score=0.85,
                confidence=0.9,
                message_content='Test message',
                conversation_history=[],
                metadata={'language': 'en'}
            )
            
            # Should handle error gracefully and return no activation
            assert result.decision == ActivationDecision.NO_ACTIVATE
            assert 'system_error' in result.reasoning[0]


if __name__ == "__main__":
    pytest.main([__file__])