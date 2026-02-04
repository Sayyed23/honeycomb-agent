"""
Tests for GUVI callback functionality.
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime
import json

from app.services.guvi_callback import GUVICallbackService, GUVIPayload, CallbackStatus
from app.services.callback_security import CallbackSecurityManager
from app.database.models import Session as SessionModel, Message, ExtractedEntity, RiskAssessment


class TestGUVICallbackService:
    """Test GUVI callback service functionality."""
    
    @pytest.fixture
    def mock_session(self):
        """Create a mock session for testing."""
        session = Mock(spec=SessionModel)
        session.id = "test-session-uuid"
        session.session_id = "test-session-123"
        session.risk_score = 0.85
        session.confidence_level = 0.90
        session.persona_type = "digitally_naive"
        session.status = "completed"
        session.start_time = datetime(2024, 1, 1, 10, 0, 0)
        session.end_time = datetime(2024, 1, 1, 10, 5, 0)
        session.total_turns = 5
        session.engagement_duration = 300
        return session
    
    @pytest.fixture
    def mock_db(self, mock_session):
        """Create a mock database session."""
        db = Mock()
        
        # Mock session query
        db.query.return_value.filter.return_value.first.return_value = mock_session
        
        # Mock risk assessments
        risk_assessment = Mock()
        risk_assessment.risk_score = 0.85
        risk_assessment.confidence = 0.90
        risk_assessment.detection_method = "ml_model"
        risk_assessment.risk_factors = {"factors": ["financial_request", "urgency"]}
        
        db.query.return_value.filter.return_value.all.return_value = [risk_assessment]
        
        # Mock entities
        entity = Mock()
        entity.entity_type = "upi_id"
        entity.entity_value = "test@upi"
        entity.confidence_score = 0.95
        entity.extraction_method = "regex"
        entity.context = "Please send money to test@upi"
        entity.verified = False
        entity.created_at = datetime(2024, 1, 1, 10, 2, 0)
        
        # Mock messages
        message = Mock()
        message.role = "user"
        message.content = "Please send money urgently"
        message.language = "en"
        message.timestamp = datetime(2024, 1, 1, 10, 1, 0)
        
        return db
    
    def test_generate_callback_payload(self, mock_db, mock_session):
        """Test callback payload generation."""
        service = GUVICallbackService()
        
        # Configure mock queries for different entity types
        mock_db.query.return_value.filter.return_value.first.return_value = mock_session
        
        # Mock risk assessments query
        risk_assessment = Mock()
        risk_assessment.risk_score = 0.85
        risk_assessment.confidence = 0.90
        risk_assessment.detection_method = "ml_model"
        risk_assessment.risk_factors = {"factors": ["financial_request"]}
        mock_db.query.return_value.filter.return_value.all.return_value = [risk_assessment]
        
        # Mock entities query
        entity = Mock()
        entity.entity_type = "upi_id"
        entity.entity_value = "test@upi"
        entity.confidence_score = 0.95
        entity.extraction_method = "regex"
        entity.context = "Send money to test@upi"
        entity.verified = False
        entity.created_at = datetime(2024, 1, 1, 10, 2, 0)
        
        # Configure the query chain for entities
        mock_db.query.return_value.filter.return_value.all.return_value = [entity]
        
        # Mock messages query
        message = Mock()
        message.role = "user"
        message.content = "Please send money"
        message.language = "en"
        message.timestamp = datetime(2024, 1, 1, 10, 1, 0)
        mock_db.query.return_value.filter.return_value.order_by.return_value.all.return_value = [message]
        
        payload = service.generate_callback_payload(mock_db, "test-session-123")
        
        assert payload.sessionId == "test-session-123"
        assert payload.detectionResult["isScam"] is True
        assert payload.detectionResult["riskScore"] == 0.85
        assert len(payload.extractedEntities) == 1
        assert payload.extractedEntities[0]["type"] == "upi_id"
        assert payload.confidence > 0.0
        assert "systemMetrics" in payload.__dict__
    
    def test_generate_callback_payload_session_not_found(self, mock_db):
        """Test payload generation with non-existent session."""
        service = GUVICallbackService()
        
        # Mock session not found
        mock_db.query.return_value.filter.return_value.first.return_value = None
        
        with pytest.raises(ValueError, match="Session .* not found"):
            service.generate_callback_payload(mock_db, "nonexistent-session")
    
    def test_generate_callback_payload_session_not_completed(self, mock_db, mock_session):
        """Test payload generation with incomplete session."""
        service = GUVICallbackService()
        
        # Mock incomplete session
        mock_session.status = "active"
        mock_db.query.return_value.filter.return_value.first.return_value = mock_session
        
        with pytest.raises(ValueError, match="Session .* is not completed"):
            service.generate_callback_payload(mock_db, "test-session-123")


class TestCallbackSecurityManager:
    """Test callback security manager functionality."""
    
    @pytest.fixture
    def sample_payload(self):
        """Create a sample callback payload for testing."""
        return {
            "sessionId": "test-session-123",
            "detectionResult": {
                "isScam": True,
                "riskScore": 0.85,
                "confidence": 0.90,
                "detectionMethods": ["ml_model", "rule_based"],
                "riskFactors": ["financial_request", "urgency"]
            },
            "extractedEntities": [
                {
                    "type": "upi_id",
                    "value": "scammer@upi",
                    "confidence": 0.95,
                    "extractionMethod": "regex",
                    "context": "Send money to scammer@upi immediately"
                }
            ],
            "conversationSummary": "Session Duration: 300 seconds | Initial Message: Please send money urgently | Final Message: Thank you for helping",
            "confidence": 0.88,
            "timestamp": "2024-01-01T10:05:00Z",
            "systemMetrics": {
                "sessionDuration": 300,
                "totalTurns": 5,
                "entityCounts": {"upi_id": 1}
            }
        }
    
    def test_sanitize_payload_for_transmission(self, sample_payload):
        """Test payload sanitization for secure transmission."""
        security_manager = CallbackSecurityManager()
        
        sanitized = security_manager.sanitize_payload_for_transmission(sample_payload)
        
        # Check that sensitive detection details are removed
        assert "detectionMethods" not in sanitized["detectionResult"]
        assert "riskFactors" not in sanitized["detectionResult"]
        assert sanitized["detectionResult"]["detectionSummary"] == "Automated scam detection analysis completed"
        
        # Check that entity values are hashed
        assert "valueHash" in sanitized["extractedEntities"][0]
        assert "partialValue" in sanitized["extractedEntities"][0]
        assert "value" not in sanitized["extractedEntities"][0]
        
        # Check that conversation content is sanitized
        assert "[Content sanitized for security]" in sanitized["conversationSummary"]
        
        # Check security metadata is added
        assert sanitized["security"]["sanitized"] is True
        assert "sanitizedAt" in sanitized["security"]
    
    def test_create_partial_value(self):
        """Test partial value creation for different entity types."""
        security_manager = CallbackSecurityManager()
        
        # Test UPI ID
        partial_upi = security_manager._create_partial_value("test@paytm", "upi_id")
        assert partial_upi == "****@paytm"
        
        # Test phone number
        partial_phone = security_manager._create_partial_value("9876543210", "phone_number")
        assert partial_phone == "98****10"
        
        # Test email
        partial_email = security_manager._create_partial_value("test@example.com", "email")
        assert partial_email == "****@example.com"
        
        # Test bank account
        partial_bank = security_manager._create_partial_value("1234567890", "bank_account")
        assert partial_bank == "****7890"
    
    def test_generate_callback_signature(self, sample_payload):
        """Test callback signature generation."""
        security_manager = CallbackSecurityManager()
        
        signature = security_manager.generate_callback_signature(sample_payload)
        
        assert isinstance(signature, str)
        assert len(signature) == 64  # SHA256 hex digest length
        
        # Test signature consistency
        signature2 = security_manager.generate_callback_signature(sample_payload)
        assert signature == signature2
    
    def test_verify_callback_integrity(self, sample_payload):
        """Test callback integrity verification."""
        security_manager = CallbackSecurityManager()
        
        # Generate signature
        signature = security_manager.generate_callback_signature(sample_payload)
        
        # Verify with correct signature
        assert security_manager.verify_callback_integrity(sample_payload, signature) is True
        
        # Verify with incorrect signature
        assert security_manager.verify_callback_integrity(sample_payload, "invalid_signature") is False
    
    def test_audit_callback_security(self, sample_payload):
        """Test security audit functionality."""
        security_manager = CallbackSecurityManager()
        
        # Test unsanitized payload
        audit_results = security_manager.audit_callback_security("test-session", sample_payload)
        
        assert audit_results["security_compliant"] is False
        assert audit_results["security_checks"]["sensitive_data_exposed"] is True
        
        # Test sanitized payload
        sanitized_payload = security_manager.sanitize_payload_for_transmission(sample_payload)
        audit_results = security_manager.audit_callback_security("test-session", sanitized_payload)
        
        assert audit_results["security_compliant"] is True
        assert audit_results["security_checks"]["payload_sanitized"] is True


@pytest.mark.asyncio
class TestGUVICallbackIntegration:
    """Test GUVI callback integration scenarios."""
    
    @patch('httpx.AsyncClient')
    async def test_send_callback_success(self, mock_http_client):
        """Test successful callback sending."""
        # Mock HTTP response
        mock_response = Mock()
        mock_response.is_success = True
        mock_response.status_code = 200
        mock_response.text = "Success"
        
        mock_client_instance = AsyncMock()
        mock_client_instance.post.return_value = mock_response
        mock_http_client.return_value.__aenter__.return_value = mock_client_instance
        
        # Mock database
        mock_db = Mock()
        mock_session = Mock()
        mock_session.id = "test-uuid"
        mock_session.session_id = "test-session-123"
        mock_session.status = "completed"
        mock_session.risk_score = 0.85
        mock_session.confidence_level = 0.90
        
        mock_db.query.return_value.filter.return_value.first.return_value = mock_session
        mock_db.query.return_value.filter.return_value.all.return_value = []
        mock_db.query.return_value.filter.return_value.order_by.return_value.all.return_value = []
        
        # Mock callback record
        mock_callback = Mock()
        mock_db.add.return_value = None
        mock_db.flush.return_value = None
        mock_db.commit.return_value = None
        
        async with GUVICallbackService() as service:
            # Mock the callback record creation
            with patch.object(service, '_get_or_create_callback_record', return_value=mock_callback):
                success = await service.send_callback(mock_db, "test-session-123")
        
        assert success is True
        assert mock_callback.callback_status == CallbackStatus.SUCCESS.value
    
    @patch('httpx.AsyncClient')
    async def test_send_callback_failure(self, mock_http_client):
        """Test callback sending failure."""
        # Mock HTTP response
        mock_response = Mock()
        mock_response.is_success = False
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        
        mock_client_instance = AsyncMock()
        mock_client_instance.post.return_value = mock_response
        mock_http_client.return_value.__aenter__.return_value = mock_client_instance
        
        # Mock database
        mock_db = Mock()
        mock_session = Mock()
        mock_session.id = "test-uuid"
        mock_session.session_id = "test-session-123"
        mock_session.status = "completed"
        mock_session.risk_score = 0.85
        mock_session.confidence_level = 0.90
        
        mock_db.query.return_value.filter.return_value.first.return_value = mock_session
        mock_db.query.return_value.filter.return_value.all.return_value = []
        mock_db.query.return_value.filter.return_value.order_by.return_value.all.return_value = []
        
        # Mock callback record
        mock_callback = Mock()
        mock_db.add.return_value = None
        mock_db.flush.return_value = None
        mock_db.commit.return_value = None
        
        async with GUVICallbackService() as service:
            # Mock the callback record creation
            with patch.object(service, '_get_or_create_callback_record', return_value=mock_callback):
                success = await service.send_callback(mock_db, "test-session-123")
        
        assert success is False
        assert mock_callback.callback_status == CallbackStatus.FAILED.value