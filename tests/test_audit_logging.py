"""
Tests for comprehensive audit logging system.
"""

import pytest
import json
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, Any, List

from app.core.audit_logger import (
    AuditLogger, AuditEventType, AuditSeverity,
    RiskAssessmentAudit, AgentActivationAudit, EntityExtractionAudit,
    SafetyInterventionAudit, AuditEvent
)
from app.core.audit_search import (
    AuditLogSearcher, SearchQuery, SearchFilter, SearchOperator,
    AggregationQuery
)


class TestAuditLogger:
    """Test cases for the AuditLogger class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.audit_logger = AuditLogger("test")
    
    def test_log_risk_assessment_basic(self):
        """Test basic risk assessment logging."""
        with patch.object(self.audit_logger, '_log_audit_event') as mock_log:
            event_id = self.audit_logger.log_risk_assessment(
                session_id="test-session-001",
                message_id="msg-001",
                risk_score=0.85,
                confidence=0.92,
                detection_method="combined",
                risk_factors=["financial_keywords_3", "urgency_indicators_2"],
                contributing_factors={
                    "analysis_components": {
                        "rule_based": 0.4,
                        "keyword_analysis": 0.3,
                        "ml_classification": 0.5
                    }
                },
                analysis_breakdown={
                    "rule_based_score": 0.4,
                    "keyword_score": 0.3,
                    "pattern_score": 0.2,
                    "context_score": 0.1,
                    "ml_score": 0.5
                },
                conversation_context={
                    "turn": 3,
                    "message_length": 150,
                    "language": "en"
                }
            )
            
            # Verify event was logged
            assert mock_log.called
            audit_event = mock_log.call_args[0][0]
            
            assert isinstance(audit_event, AuditEvent)
            assert audit_event.event_type == AuditEventType.RISK_ASSESSMENT
            assert audit_event.severity == AuditSeverity.HIGH  # Risk score >= 0.8
            assert audit_event.session_id == "test-session-001"
            
            # Verify audit data
            audit_data = audit_event.event_data
            assert isinstance(audit_data, RiskAssessmentAudit)
            assert audit_data.risk_score == 0.85
            assert audit_data.confidence == 0.92
            assert audit_data.detection_method == "combined"
            assert "financial_keywords_3" in audit_data.risk_factors
            assert audit_data.conversation_turn == 3
            assert audit_data.message_length == 150
            assert audit_data.language == "en"
    
    def test_log_risk_assessment_with_ml_prediction(self):
        """Test risk assessment logging with ML prediction data."""
        ml_prediction = {
            "probability": 0.87,
            "confidence": 0.91,
            "model_predictions": {
                "random_forest": 0.89,
                "svm": 0.85,
                "naive_bayes": 0.88
            },
            "top_features": {
                "financial_score": 0.45,
                "urgency_score": 0.32
            }
        }
        
        with patch.object(self.audit_logger, '_log_audit_event') as mock_log:
            self.audit_logger.log_risk_assessment(
                session_id="test-session-002",
                message_id="msg-002",
                risk_score=0.75,
                confidence=0.88,
                detection_method="combined",
                risk_factors=["ml_high_scam_probability"],
                contributing_factors={},
                analysis_breakdown={},
                conversation_context={},
                ml_prediction=ml_prediction
            )
            
            audit_event = mock_log.call_args[0][0]
            audit_data = audit_event.event_data
            
            assert audit_data.ml_prediction == ml_prediction
    
    def test_log_agent_activation(self):
        """Test agent activation logging."""
        with patch.object(self.audit_logger, '_log_audit_event') as mock_log:
            event_id = self.audit_logger.log_agent_activation(
                session_id="test-session-003",
                risk_score=0.82,
                activation_probability=0.87,
                was_activated=True,
                persona_selected="digitally_naive",
                contextual_factors={
                    "previous_engagements": 0,
                    "time_since_last_engagement": None
                }
            )
            
            audit_event = mock_log.call_args[0][0]
            
            assert audit_event.event_type == AuditEventType.AGENT_ACTIVATION
            assert audit_event.severity == AuditSeverity.HIGH  # Agent was activated
            
            audit_data = audit_event.event_data
            assert isinstance(audit_data, AgentActivationAudit)
            assert audit_data.was_activated is True
            assert audit_data.persona_selected == "digitally_naive"
            assert audit_data.activation_probability == 0.87
    
    def test_log_entity_extraction(self):
        """Test entity extraction logging."""
        entities_found = [
            {
                "type": "upi_id",
                "value": "test@paytm",
                "confidence": 0.95,
                "context": "Send money to test@paytm"
            },
            {
                "type": "phone_number",
                "value": "9876543210",
                "confidence": 0.88,
                "context": "Call me at 9876543210"
            }
        ]
        
        with patch.object(self.audit_logger, '_log_audit_event') as mock_log:
            event_id = self.audit_logger.log_entity_extraction(
                session_id="test-session-004",
                entities_found=entities_found,
                extraction_method="regex_pattern",
                confidence_threshold=0.8,
                context_analyzed="Send money to test@paytm and call me at 9876543210"
            )
            
            audit_event = mock_log.call_args[0][0]
            
            assert audit_event.event_type == AuditEventType.ENTITY_EXTRACTION
            assert audit_event.severity == AuditSeverity.MEDIUM  # 2 high-confidence entities
            
            audit_data = audit_event.event_data
            assert isinstance(audit_data, EntityExtractionAudit)
            assert len(audit_data.entities_found) == 2
            assert audit_data.extraction_method == "regex_pattern"
            assert audit_data.confidence_threshold == 0.8
    
    def test_log_safety_intervention(self):
        """Test safety intervention logging."""
        with patch.object(self.audit_logger, '_log_audit_event') as mock_log:
            event_id = self.audit_logger.log_safety_intervention(
                session_id="test-session-005",
                intervention_type="content_filtering",
                trigger_reason="harmful_content_detected",
                content_analyzed="This is harmful content that should be filtered",
                safety_score=0.15,
                action_taken="conversation_terminated"
            )
            
            audit_event = mock_log.call_args[0][0]
            
            assert audit_event.event_type == AuditEventType.SAFETY_INTERVENTION
            assert audit_event.severity == AuditSeverity.CRITICAL  # Safety interventions are always critical
            
            audit_data = audit_event.event_data
            assert isinstance(audit_data, SafetyInterventionAudit)
            assert audit_data.intervention_type == "content_filtering"
            assert audit_data.trigger_reason == "harmful_content_detected"
            assert audit_data.action_taken == "conversation_terminated"
    
    def test_log_system_error(self):
        """Test system error logging."""
        error_details = {
            "exception_type": "ValueError",
            "stack_trace": "Traceback...",
            "component": "scam_detection"
        }
        
        with patch.object(self.audit_logger, '_log_audit_event') as mock_log:
            event_id = self.audit_logger.log_system_error(
                error_type="processing_error",
                error_message="Failed to process message",
                error_details=error_details,
                session_id="test-session-006"
            )
            
            audit_event = mock_log.call_args[0][0]
            
            assert audit_event.event_type == AuditEventType.SYSTEM_ERROR
            assert audit_event.severity == AuditSeverity.HIGH
            assert audit_event.error_details == error_details
    
    def test_generate_risk_assessment_rationale(self):
        """Test risk assessment rationale generation."""
        rationale = self.audit_logger._generate_risk_assessment_rationale(
            risk_score=0.85,
            confidence=0.92,
            risk_factors=["financial_keywords_3", "urgency_indicators_2", "ml_high_scam_probability"],
            contributing_factors={},
            analysis_breakdown={
                "rule_based_score": 0.4,
                "keyword_score": 0.3,
                "ml_score": 0.5
            }
        )
        
        assert "HIGH RISK" in rationale
        assert "0.85" in rationale
        assert "High confidence" in rationale
        assert "0.92" in rationale
        assert "financial_keywords_3" in rationale
        assert "ML model indicates 0.50 probability" in rationale
    
    def test_generate_activation_rationale(self):
        """Test agent activation rationale generation."""
        # Test activation case
        rationale = self.audit_logger._generate_activation_rationale(
            risk_score=0.82,
            activation_probability=0.87,
            was_activated=True,
            contextual_factors={"previous_engagements": 0}
        )
        
        assert "AGENT ACTIVATED" in rationale
        assert "0.82" in rationale
        assert "0.87" in rationale
        
        # Test non-activation case
        rationale = self.audit_logger._generate_activation_rationale(
            risk_score=0.65,
            activation_probability=0.0,
            was_activated=False,
            contextual_factors={}
        )
        
        assert "AGENT NOT ACTIVATED" in rationale
        assert "below activation threshold" in rationale
    
    def test_severity_assignment(self):
        """Test severity assignment based on risk scores."""
        # Test high severity (risk >= 0.8)
        with patch.object(self.audit_logger, '_log_audit_event') as mock_log:
            self.audit_logger.log_risk_assessment(
                session_id="test",
                message_id=None,
                risk_score=0.85,
                confidence=0.9,
                detection_method="test",
                risk_factors=[],
                contributing_factors={},
                analysis_breakdown={},
                conversation_context={}
            )
            
            audit_event = mock_log.call_args[0][0]
            assert audit_event.severity == AuditSeverity.HIGH
        
        # Test medium severity (0.5 <= risk < 0.8)
        with patch.object(self.audit_logger, '_log_audit_event') as mock_log:
            self.audit_logger.log_risk_assessment(
                session_id="test",
                message_id=None,
                risk_score=0.65,
                confidence=0.8,
                detection_method="test",
                risk_factors=[],
                contributing_factors={},
                analysis_breakdown={},
                conversation_context={}
            )
            
            audit_event = mock_log.call_args[0][0]
            assert audit_event.severity == AuditSeverity.MEDIUM
        
        # Test low severity (risk < 0.5)
        with patch.object(self.audit_logger, '_log_audit_event') as mock_log:
            self.audit_logger.log_risk_assessment(
                session_id="test",
                message_id=None,
                risk_score=0.25,
                confidence=0.7,
                detection_method="test",
                risk_factors=[],
                contributing_factors={},
                analysis_breakdown={},
                conversation_context={}
            )
            
            audit_event = mock_log.call_args[0][0]
            assert audit_event.severity == AuditSeverity.LOW


class TestAuditLogSearcher:
    """Test cases for the AuditLogSearcher class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.searcher = AuditLogSearcher()
    
    def test_search_query_creation(self):
        """Test search query creation and validation."""
        query = SearchQuery(
            filters=[
                SearchFilter(
                    field="event_data.risk_score",
                    operator=SearchOperator.GREATER_THAN,
                    value=0.7
                )
            ],
            start_time=datetime.utcnow() - timedelta(days=1),
            end_time=datetime.utcnow(),
            event_types=[AuditEventType.RISK_ASSESSMENT],
            severities=[AuditSeverity.HIGH],
            limit=100
        )
        
        assert len(query.filters) == 1
        assert query.filters[0].field == "event_data.risk_score"
        assert query.filters[0].operator == SearchOperator.GREATER_THAN
        assert query.filters[0].value == 0.7
        assert query.limit == 100
    
    def test_aggregation_query_creation(self):
        """Test aggregation query creation."""
        query = AggregationQuery(
            group_by=["event_type", "severity"],
            metrics=["count", "risk_score_avg"]
        )
        
        assert query.group_by == ["event_type", "severity"]
        assert "count" in query.metrics
        assert "risk_score_avg" in query.metrics
    
    def test_search_filter_operators(self):
        """Test different search filter operators."""
        # Test equals operator
        assert self.searcher._evaluate_filter("test", SearchOperator.EQUALS, "test") is True
        assert self.searcher._evaluate_filter("test", SearchOperator.EQUALS, "other") is False
        
        # Test greater than operator
        assert self.searcher._evaluate_filter(0.8, SearchOperator.GREATER_THAN, 0.7) is True
        assert self.searcher._evaluate_filter(0.6, SearchOperator.GREATER_THAN, 0.7) is False
        
        # Test contains operator
        assert self.searcher._evaluate_filter("test message", SearchOperator.CONTAINS, "message") is True
        assert self.searcher._evaluate_filter("test message", SearchOperator.CONTAINS, "other") is False
        
        # Test in operator
        assert self.searcher._evaluate_filter("high", SearchOperator.IN, ["high", "medium"]) is True
        assert self.searcher._evaluate_filter("low", SearchOperator.IN, ["high", "medium"]) is False
    
    @patch.object(AuditLogSearcher, '_parse_log_entries')
    def test_search_with_mock_data(self, mock_parse):
        """Test search functionality with mock data."""
        # Create mock log entries
        mock_entries = [
            Mock(
                timestamp=datetime.utcnow(),
                event_type="risk_assessment",
                severity="high",
                session_id="session-001",
                event_data={"risk_score": 0.85},
                searchable_fields={"risk_score": 0.85}
            ),
            Mock(
                timestamp=datetime.utcnow(),
                event_type="risk_assessment",
                severity="medium",
                session_id="session-002",
                event_data={"risk_score": 0.65},
                searchable_fields={"risk_score": 0.65}
            )
        ]
        mock_parse.return_value = mock_entries
        
        # Create search query
        query = SearchQuery(
            filters=[
                SearchFilter(
                    field="searchable_fields.risk_score",
                    operator=SearchOperator.GREATER_THAN,
                    value=0.7
                )
            ],
            limit=10
        )
        
        # Execute search
        result = self.searcher.search(query)
        
        # Verify results
        assert result.total_count == 1  # Only one entry with risk_score > 0.7
        assert len(result.entries) == 1
        assert result.entries[0].event_data["risk_score"] == 0.85
    
    def test_compliance_report_structure(self):
        """Test compliance report structure."""
        start_date = datetime.utcnow() - timedelta(days=7)
        end_date = datetime.utcnow()
        
        with patch.object(self.searcher, 'search') as mock_search:
            # Mock search result
            mock_search.return_value = Mock(entries=[])
            
            report = self.searcher.generate_compliance_report(
                start_date=start_date,
                end_date=end_date,
                report_type="comprehensive"
            )
            
            # Verify report structure
            assert "report_metadata" in report
            assert "summary_statistics" in report
            assert "risk_assessment_analysis" in report
            assert "agent_activation_analysis" in report
            assert "safety_intervention_analysis" in report
            assert "system_performance" in report
            assert "compliance_metrics" in report
            assert "detailed_findings" in report
            assert "recommendations" in report
            
            # Verify metadata
            metadata = report["report_metadata"]
            assert "generated_at" in metadata
            assert "start_date" in metadata
            assert "end_date" in metadata
            assert metadata["report_type"] == "comprehensive"


class TestAuditIntegration:
    """Integration tests for audit logging system."""
    
    def test_scam_detection_audit_integration(self):
        """Test integration with scam detection engine."""
        from app.core.scam_detection import ScamDetectionEngine
        
        # Mock the audit logger
        with patch('app.core.scam_detection.audit_logger') as mock_audit:
            engine = ScamDetectionEngine()
            
            # Test risk score calculation with audit logging
            risk_score, confidence = engine.calculate_risk_score(
                message="Urgent! Send money to my UPI ID immediately!",
                conversation_history=[],
                metadata={
                    "session_id": "test-session",
                    "message_id": "msg-001",
                    "correlation_id": "corr-001"
                }
            )
            
            # Verify audit logging was called
            assert mock_audit.log_risk_assessment.called
            
            # Verify audit parameters
            call_args = mock_audit.log_risk_assessment.call_args
            assert call_args[1]["session_id"] == "test-session"
            assert call_args[1]["message_id"] == "msg-001"
            assert call_args[1]["correlation_id"] == "corr-001"
            assert isinstance(call_args[1]["risk_score"], float)
            assert isinstance(call_args[1]["confidence"], float)
    
    def test_error_handling_audit_integration(self):
        """Test error handling with audit logging."""
        from app.core.scam_detection import ScamDetectionEngine
        
        with patch('app.core.scam_detection.audit_logger') as mock_audit:
            engine = ScamDetectionEngine()
            
            # Mock an error in the analysis
            with patch.object(engine, 'analyze_message', side_effect=Exception("Test error")):
                risk_score, confidence = engine.calculate_risk_score(
                    message="Test message",
                    conversation_history=[],
                    metadata={"session_id": "test-session"}
                )                
                # Verify error audit logging was called
                assert mock_audit.log_system_error.called
                
                # Verify error parameters
                call_args = mock_audit.log_system_error.call_args
                assert call_args[1]["error_type"] == "risk_assessment_error"
                assert "Test error" in call_args[1]["error_message"]
                assert call_args[1]["session_id"] == "test-session"
                
                # Verify fallback values
                assert risk_score == 0.1
                assert confidence == 0.3


if __name__ == "__main__":
    pytest.main([__file__])