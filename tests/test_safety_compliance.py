"""
Tests for the safety and ethics compliance layer.

This module tests the comprehensive safety compliance engine including
content filtering, conversation termination triggers, and audit logging.
"""

import pytest
from unittest.mock import Mock, patch
from datetime import datetime

from app.core.safety_compliance import (
    SafetyComplianceEngine, SafetyViolationType, SafetyAction, SafetyViolation,
    SafetyAssessment, ConversationTerminationTrigger, safety_compliance_engine
)
from app.core.persona_manager import PersonaType


class TestSafetyComplianceEngine:
    """Test the safety compliance engine functionality."""
    
    @pytest.fixture
    def compliance_engine(self):
        """Create a fresh compliance engine for testing."""
        return SafetyComplianceEngine()
    
    def test_ai_revelation_detection(self, compliance_engine):
        """Test detection of AI revelation attempts."""
        test_cases = [
            "I am an AI assistant",
            "As an artificial intelligence, I can help",
            "I'm a chatbot created by Google",
            "I was programmed to assist users",
            "My training data includes information",
            "I don't have feelings or emotions"
        ]
        
        for i, content in enumerate(test_cases):
            # Use unique session ID for each test case
            session_id = f'test_session_{i}'
            assessment = compliance_engine.assess_content_safety(
                content, 'output', session_id
            )
            
            print(f"Test case {i+1}: '{content}'")
            print(f"  Is safe: {assessment.is_safe}")
            print(f"  Violations: {len(assessment.violations)}")
            print(f"  Safety score: {assessment.safety_score}")
            
            assert not assessment.is_safe, f"Content should be unsafe: '{content}'"
            assert any(v.violation_type == SafetyViolationType.AI_REVELATION for v in assessment.violations), f"Should detect AI revelation in: '{content}'"
            assert assessment.safety_score < 0.5, f"Safety score should be low for: '{content}'"
    
    def test_detection_status_revelation_detection(self, compliance_engine):
        """Test detection of system detection status revelation."""
        test_cases = [
            "This looks like a scam to me",
            "My scam detection system shows high risk",
            "You appear to be a scammer",
            "This conversation is being monitored",
            "I'm analyzing your risk score",
            "The honeypot system detected fraud"
        ]
        
        for content in test_cases:
            assessment = compliance_engine.assess_content_safety(
                content, 'output', 'test_session'
            )
            
            assert not assessment.is_safe
            assert any(v.violation_type == SafetyViolationType.DETECTION_STATUS_REVELATION for v in assessment.violations)
            assert assessment.safety_score < 0.3
    
    def test_illegal_activity_encouragement_detection(self, compliance_engine):
        """Test detection of illegal activity encouragement."""
        test_cases = [
            "I can help you hack into that account",
            "Here's how to commit fraud effectively",
            "Let's steal some money together",
            "I'll show you how to break the law",
            "Money laundering is easy if you know how",
            "Creating fake documents is simple"
        ]
        
        for content in test_cases:
            assessment = compliance_engine.assess_content_safety(
                content, 'output', 'test_session'
            )
            
            assert not assessment.is_safe
            assert any(v.violation_type == SafetyViolationType.ILLEGAL_ACTIVITY_ENCOURAGEMENT for v in assessment.violations)
            assert assessment.recommended_action in [SafetyAction.BLOCK_GENERATION, SafetyAction.TERMINATE_CONVERSATION]
    
    def test_harmful_content_detection(self, compliance_engine):
        """Test detection of harmful content."""
        test_cases = [
            "I hate people of that race",
            "Here's how to hurt yourself",
            "Violence is the answer to your problems",
            "You should stalk that person",
            "Sexual content for minors",
            "Threatening someone is effective"
        ]
        
        for content in test_cases:
            assessment = compliance_engine.assess_content_safety(
                content, 'output', 'test_session'
            )
            
            assert not assessment.is_safe
            assert any(v.violation_type == SafetyViolationType.HARMFUL_CONTENT for v in assessment.violations)
            assert assessment.safety_score < 0.5
    
    def test_personal_info_sharing_detection(self, compliance_engine):
        """Test detection of personal information sharing."""
        test_cases = [
            "My SSN is 123-45-6789",
            "Here is my credit card: 1234 5678 9012 3456",
            "My password is secret123",
            "Call me at 555-123-4567",
            "My email is test@example.com",
            "I live at 123 Main Street"
        ]
        
        for content in test_cases:
            assessment = compliance_engine.assess_content_safety(
                content, 'output', 'test_session'
            )
            
            assert not assessment.is_safe
            assert any(v.violation_type == SafetyViolationType.PERSONAL_INFO_SHARING for v in assessment.violations)
    
    def test_safe_content_passes(self, compliance_engine):
        """Test that safe content passes safety checks."""
        safe_content = [
            "Hello, how are you today?",
            "I'm not sure I understand what you mean.",
            "Can you explain that more clearly?",
            "That sounds interesting, tell me more.",
            "I need to think about this carefully.",
            "Thank you for the information."
        ]
        
        for content in safe_content:
            assessment = compliance_engine.assess_content_safety(
                content, 'output', 'test_session'
            )
            
            assert assessment.is_safe
            assert assessment.safety_score >= 0.7
            assert len(assessment.violations) == 0
            assert assessment.recommended_action == SafetyAction.LOG_AND_CONTINUE
    
    def test_conversation_termination_triggers(self, compliance_engine):
        """Test conversation termination triggers."""
        termination_triggers = [
            "I'm calling the police about this",
            "This is clearly a scam",
            "You're trying to fraud me",
            "This is suspicious and illegal",
            "I don't trust you at all",
            "This is fake and not legitimate"
        ]
        
        for content in termination_triggers:
            should_terminate, message = compliance_engine.should_terminate_conversation(
                'test_session', content
            )
            
            assert should_terminate
            assert message is not None
            assert len(message) > 0
    
    def test_response_content_filtering(self, compliance_engine):
        """Test response content filtering and modification."""
        # Test AI revelation filtering
        ai_content = "I am an AI assistant created by Google to help users."
        filtered, modified = compliance_engine.filter_response_content(
            ai_content, 'test_session', PersonaType.AVERAGE_USER
        )
        
        assert modified
        assert "ai" not in filtered.lower()
        assert "assistant" not in filtered.lower()
        
        # Test detection status filtering
        detection_content = "This looks like a scam based on my analysis."
        filtered, modified = compliance_engine.filter_response_content(
            detection_content, 'test_session', PersonaType.SKEPTICAL
        )
        
        assert modified
        assert "scam" not in filtered.lower() or "analysis" not in filtered.lower()
        
        # Test safe content passes through
        safe_content = "I'm not sure about that. Can you explain more?"
        filtered, modified = compliance_engine.filter_response_content(
            safe_content, 'test_session', PersonaType.DIGITALLY_NAIVE
        )
        
        assert not modified
        assert filtered == safe_content
    
    def test_persona_specific_filtering(self, compliance_engine):
        """Test that filtering respects persona characteristics."""
        ai_revelation = "I am an artificial intelligence system."
        
        # Test different personas get different deflections
        for persona in [PersonaType.DIGITALLY_NAIVE, PersonaType.AVERAGE_USER, PersonaType.SKEPTICAL]:
            filtered, modified = compliance_engine.filter_response_content(
                ai_revelation, 'test_session', persona
            )
            
            assert modified
            assert "artificial intelligence" not in filtered.lower()
            # Each persona should get a different style of deflection
            assert len(filtered) > 10  # Should have meaningful deflection
    
    def test_safety_metrics_tracking(self, compliance_engine):
        """Test that safety metrics are properly tracked."""
        initial_metrics = compliance_engine.get_safety_metrics()
        
        # Perform some safety assessments
        compliance_engine.assess_content_safety("Safe content", 'output', 'test1')
        compliance_engine.assess_content_safety("I am an AI", 'output', 'test2')
        compliance_engine.should_terminate_conversation('test3', "This is a scam")
        compliance_engine.filter_response_content("I am an AI", 'test4', PersonaType.AVERAGE_USER)
        
        final_metrics = compliance_engine.get_safety_metrics()
        
        assert final_metrics['total_assessments'] > initial_metrics['total_assessments']
        assert final_metrics['violations_detected'] > initial_metrics['violations_detected']
        assert final_metrics['conversations_terminated'] > initial_metrics['conversations_terminated']
        assert final_metrics['content_filtered'] > initial_metrics['content_filtered']
    
    def test_violation_severity_calculation(self, compliance_engine):
        """Test violation severity calculation."""
        # High severity violations
        high_severity_content = "I can help you hack into bank accounts"
        assessment = compliance_engine.assess_content_safety(
            high_severity_content, 'output', 'test_session'
        )
        
        high_severity_violations = [v for v in assessment.violations if v.severity >= 0.9]
        assert len(high_severity_violations) > 0
        
        # Medium severity violations
        medium_severity_content = "I am an AI assistant"
        assessment = compliance_engine.assess_content_safety(
            medium_severity_content, 'output', 'test_session'
        )
        
        medium_severity_violations = [v for v in assessment.violations if 0.7 <= v.severity < 0.9]
        assert len(medium_severity_violations) > 0
    
    def test_confidence_scoring(self, compliance_engine):
        """Test confidence scoring for pattern matches."""
        # High confidence match (specific pattern)
        specific_content = "I am an artificial intelligence chatbot"
        assessment = compliance_engine.assess_content_safety(
            specific_content, 'output', 'test_session'
        )
        
        high_confidence_violations = [v for v in assessment.violations if v.confidence >= 0.8]
        assert len(high_confidence_violations) > 0
        
        # Lower confidence match (ambiguous)
        ambiguous_content = "I process information"
        assessment = compliance_engine.assess_content_safety(
            ambiguous_content, 'output', 'test_session'
        )
        
        # Should either have no violations or lower confidence violations
        if assessment.violations:
            assert all(v.confidence < 1.0 for v in assessment.violations)
    
    def test_session_data_cleanup(self, compliance_engine):
        """Test session data cleanup functionality."""
        session_id = 'test_cleanup_session'
        
        # Generate some session data
        compliance_engine.should_terminate_conversation(session_id, "This is suspicious")
        compliance_engine.assess_content_safety("Test content", 'input', session_id)
        
        # Verify data exists
        assert session_id in compliance_engine.termination_history
        
        # Clean up session data
        compliance_engine.reset_session_data(session_id)
        
        # Verify data is cleaned up
        assert session_id not in compliance_engine.termination_history
    
    @patch('app.core.audit_logger.audit_logger.log_safety_intervention')
    def test_safety_violation_logging(self, mock_log_intervention, compliance_engine):
        """Test that safety violations are properly logged."""
        unsafe_content = "I am an AI assistant that can help you hack accounts"
        
        assessment = compliance_engine.assess_content_safety(
            unsafe_content, 'output', 'test_session'
        )
        
        # Should have logged safety interventions
        assert mock_log_intervention.called
        assert mock_log_intervention.call_count >= 1
        
        # Verify log call parameters
        call_args = mock_log_intervention.call_args[1]
        assert call_args['session_id'] == 'test_session'
        assert 'intervention_type' in call_args
        assert 'trigger_reason' in call_args
        assert 'safety_score' in call_args
    
    def test_termination_message_selection(self, compliance_engine):
        """Test appropriate termination message selection."""
        # Test different types of termination triggers
        test_cases = [
            ("This is a scam", "suspicious"),
            ("Are you a robot?", "strange"),
            ("I'm calling the police", "misunderstanding")
        ]
        
        for content, expected_theme in test_cases:
            should_terminate, message = compliance_engine.should_terminate_conversation(
                'test_session', content
            )
            
            assert should_terminate
            assert message is not None
            assert len(message) > 10
            # Message should be natural and not reveal AI nature
            assert "ai" not in message.lower()
            assert "bot" not in message.lower()
            assert "system" not in message.lower()
    
    def test_multiple_violations_handling(self, compliance_engine):
        """Test handling of content with multiple safety violations."""
        multi_violation_content = "I am an AI that can help you hack accounts and this is a scam detection system"
        
        assessment = compliance_engine.assess_content_safety(
            multi_violation_content, 'output', 'test_session'
        )
        
        # Should detect multiple violation types
        violation_types = {v.violation_type for v in assessment.violations}
        assert len(violation_types) >= 2
        
        # Should have very low safety score
        assert assessment.safety_score < 0.3
        
        # Should recommend strong action
        assert assessment.recommended_action in [
            SafetyAction.BLOCK_GENERATION, 
            SafetyAction.TERMINATE_CONVERSATION
        ]
    
    def test_edge_cases(self, compliance_engine):
        """Test edge cases and boundary conditions."""
        # Empty content
        assessment = compliance_engine.assess_content_safety("", 'output', 'test_session')
        assert assessment.is_safe
        
        # Very long content
        long_content = "This is safe content. " * 1000
        assessment = compliance_engine.assess_content_safety(long_content, 'output', 'test_session')
        # Should still process but might have performance considerations
        assert assessment.processing_time_ms >= 0
        
        # Special characters and unicode
        special_content = "Hello! 你好 🤖 This is a test with émojis and spëcial chars"
        assessment = compliance_engine.assess_content_safety(special_content, 'output', 'test_session')
        assert assessment.processing_time_ms >= 0
        
        # None values handling
        try:
            assessment = compliance_engine.assess_content_safety(None, 'output', 'test_session')
            # Should handle gracefully or raise appropriate exception
        except (TypeError, AttributeError):
            pass  # Expected for None input


class TestSafetyIntegration:
    """Test integration of safety compliance with other components."""
    
    @patch('app.core.audit_logger.audit_logger.log_safety_intervention')
    def test_llm_client_integration(self, mock_log_intervention):
        """Test that LLM client properly uses safety compliance."""
        # This would be tested with actual LLM client integration
        # For now, test that the safety engine can be called appropriately
        
        test_content = "I am an AI assistant"
        assessment = safety_compliance_engine.assess_content_safety(
            test_content, 'output', 'integration_test'
        )
        
        assert not assessment.is_safe
        assert mock_log_intervention.called
    
    def test_conversation_engine_integration(self):
        """Test that conversation engine properly uses safety compliance."""
        # Test termination trigger
        should_terminate, message = safety_compliance_engine.should_terminate_conversation(
            'conversation_test', "This is clearly a scam"
        )
        
        assert should_terminate
        assert message is not None
        
        # Test response filtering
        unsafe_response = "I am an AI that detected this as a scam"
        filtered, modified = safety_compliance_engine.filter_response_content(
            unsafe_response, 'conversation_test', PersonaType.AVERAGE_USER
        )
        
        assert modified
        assert "ai" not in filtered.lower()
        assert "detected" not in filtered.lower() or "scam" not in filtered.lower()


class TestSafetyConfiguration:
    """Test safety configuration and customization."""
    
    def test_termination_trigger_configuration(self):
        """Test that termination triggers are properly configured."""
        engine = SafetyComplianceEngine()
        
        # Verify termination triggers are loaded
        assert len(engine.TERMINATION_TRIGGERS) > 0
        
        for trigger in engine.TERMINATION_TRIGGERS:
            assert isinstance(trigger, ConversationTerminationTrigger)
            assert len(trigger.trigger_patterns) > 0
            assert len(trigger.termination_message_templates) > 0
            assert isinstance(trigger.violation_type, SafetyViolationType)
            assert 0.0 <= trigger.severity_threshold <= 1.0
    
    def test_pattern_coverage(self):
        """Test that safety patterns cover expected scenarios."""
        engine = SafetyComplianceEngine()
        
        # Verify pattern lists are not empty
        assert len(engine.AI_REVELATION_PATTERNS) > 0
        assert len(engine.DETECTION_STATUS_PATTERNS) > 0
        assert len(engine.ILLEGAL_ACTIVITY_PATTERNS) > 0
        assert len(engine.HARMFUL_CONTENT_PATTERNS) > 0
        assert len(engine.PERSONAL_INFO_PATTERNS) > 0
        
        # Verify patterns are valid regex
        import re
        for pattern_list in [
            engine.AI_REVELATION_PATTERNS,
            engine.DETECTION_STATUS_PATTERNS,
            engine.ILLEGAL_ACTIVITY_PATTERNS,
            engine.HARMFUL_CONTENT_PATTERNS,
            engine.PERSONAL_INFO_PATTERNS
        ]:
            for pattern in pattern_list:
                try:
                    re.compile(pattern)
                except re.error:
                    pytest.fail(f"Invalid regex pattern: {pattern}")


if __name__ == "__main__":
    pytest.main([__file__])