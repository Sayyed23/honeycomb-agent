"""
Unit tests for GUVI callback functionality (no database dependencies).
"""

import pytest
from unittest.mock import Mock
from datetime import datetime

from app.services.callback_security import CallbackSecurityManager


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
    
    def test_create_partial_value_upi(self):
        """Test partial value creation for UPI IDs."""
        security_manager = CallbackSecurityManager()
        
        partial_upi = security_manager._create_partial_value("test@paytm", "upi_id")
        assert partial_upi == "****@paytm"
        
        partial_upi2 = security_manager._create_partial_value("user@gpay", "upi_id")
        assert partial_upi2 == "****@gpay"
    
    def test_create_partial_value_phone(self):
        """Test partial value creation for phone numbers."""
        security_manager = CallbackSecurityManager()
        
        partial_phone = security_manager._create_partial_value("9876543210", "phone_number")
        assert partial_phone == "98****10"
        
        partial_phone2 = security_manager._create_partial_value("+919876543210", "phone_number")
        assert partial_phone2 == "+9****10"
    
    def test_create_partial_value_email(self):
        """Test partial value creation for emails."""
        security_manager = CallbackSecurityManager()
        
        partial_email = security_manager._create_partial_value("test@example.com", "email")
        assert partial_email == "****@example.com"
        
        partial_email2 = security_manager._create_partial_value("user@gmail.com", "email")
        assert partial_email2 == "****@gmail.com"
    
    def test_create_partial_value_bank_account(self):
        """Test partial value creation for bank accounts."""
        security_manager = CallbackSecurityManager()
        
        partial_bank = security_manager._create_partial_value("1234567890", "bank_account")
        assert partial_bank == "****7890"
        
        partial_bank2 = security_manager._create_partial_value("9876543210123456", "bank_account")
        assert partial_bank2 == "****3456"
    
    def test_create_partial_value_url(self):
        """Test partial value creation for URLs."""
        security_manager = CallbackSecurityManager()
        
        partial_url = security_manager._create_partial_value("https://example.com/malicious", "url")
        assert partial_url == "https://example.com/****"
        
        partial_url2 = security_manager._create_partial_value("http://scam-site.net/page", "url")
        assert partial_url2 == "http://scam-site.net/****"
    
    def test_hash_sensitive_value(self):
        """Test sensitive value hashing."""
        security_manager = CallbackSecurityManager()
        
        hash1 = security_manager._hash_sensitive_value("test@upi")
        hash2 = security_manager._hash_sensitive_value("test@upi")
        hash3 = security_manager._hash_sensitive_value("different@upi")
        
        # Same value should produce same hash
        assert hash1 == hash2
        
        # Different values should produce different hashes
        assert hash1 != hash3
        
        # Hash should be hex string
        assert len(hash1) == 64  # SHA256 hex digest
        assert all(c in '0123456789abcdef' for c in hash1)
    
    def test_generate_callback_signature(self, sample_payload):
        """Test callback signature generation."""
        security_manager = CallbackSecurityManager()
        
        signature = security_manager.generate_callback_signature(sample_payload)
        
        assert isinstance(signature, str)
        assert len(signature) == 64  # SHA256 hex digest length
        
        # Test signature consistency
        signature2 = security_manager.generate_callback_signature(sample_payload)
        assert signature == signature2
        
        # Test different payload produces different signature
        modified_payload = sample_payload.copy()
        modified_payload["sessionId"] = "different-session"
        signature3 = security_manager.generate_callback_signature(modified_payload)
        assert signature != signature3
    
    def test_verify_callback_integrity(self, sample_payload):
        """Test callback integrity verification."""
        security_manager = CallbackSecurityManager()
        
        # Generate signature
        signature = security_manager.generate_callback_signature(sample_payload)
        
        # Verify with correct signature
        assert security_manager.verify_callback_integrity(sample_payload, signature) is True
        
        # Verify with incorrect signature
        assert security_manager.verify_callback_integrity(sample_payload, "invalid_signature") is False
        
        # Verify with modified payload
        modified_payload = sample_payload.copy()
        modified_payload["confidence"] = 0.99
        assert security_manager.verify_callback_integrity(modified_payload, signature) is False
    
    def test_audit_callback_security_unsanitized(self, sample_payload):
        """Test security audit for unsanitized payload."""
        security_manager = CallbackSecurityManager()
        
        audit_results = security_manager.audit_callback_security("test-session", sample_payload)
        
        assert audit_results["session_id"] == "test-session"
        assert audit_results["security_compliant"] is False
        assert audit_results["security_checks"]["sensitive_data_exposed"] is True
        assert audit_results["security_checks"]["payload_sanitized"] is False
        assert "audit_timestamp" in audit_results
    
    def test_audit_callback_security_sanitized(self, sample_payload):
        """Test security audit for sanitized payload."""
        security_manager = CallbackSecurityManager()
        
        # First sanitize the payload
        sanitized_payload = security_manager.sanitize_payload_for_transmission(sample_payload)
        
        # Then audit it
        audit_results = security_manager.audit_callback_security("test-session", sanitized_payload)
        
        assert audit_results["session_id"] == "test-session"
        assert audit_results["security_compliant"] is True
        assert audit_results["security_checks"]["payload_sanitized"] is True
        assert audit_results["security_checks"]["sensitive_data_exposed"] is False
        assert audit_results["security_checks"]["security_metadata_present"] is True
    
    def test_sanitize_conversation_summary(self):
        """Test conversation summary sanitization."""
        security_manager = CallbackSecurityManager()
        
        original_summary = "Session Duration: 300 seconds | Total Turns: 5 | Initial Message: Please send money to test@upi | Final Message: Thank you for your help"
        
        sanitized_summary = security_manager._sanitize_conversation_summary(original_summary)
        
        assert "Session Duration: 300 seconds" in sanitized_summary
        assert "Total Turns: 5" in sanitized_summary
        assert "Initial Message: [Content sanitized for security]" in sanitized_summary
        assert "Final Message: [Content sanitized for security]" in sanitized_summary
        assert "test@upi" not in sanitized_summary
    
    def test_sanitize_extracted_entities(self):
        """Test extracted entities sanitization."""
        security_manager = CallbackSecurityManager()
        
        entities = [
            {
                "type": "upi_id",
                "value": "scammer@paytm",
                "confidence": 0.95,
                "extractionMethod": "regex",
                "context": "Send money to scammer@paytm now",
                "verified": False,
                "extractedAt": "2024-01-01T10:00:00Z"
            },
            {
                "type": "phone_number",
                "value": "9876543210",
                "confidence": 0.88,
                "extractionMethod": "regex",
                "context": "Call me at 9876543210",
                "verified": True,
                "extractedAt": "2024-01-01T10:01:00Z"
            }
        ]
        
        sanitized_entities = security_manager._sanitize_extracted_entities(entities)
        
        assert len(sanitized_entities) == 2
        
        # Check UPI entity
        upi_entity = sanitized_entities[0]
        assert upi_entity["type"] == "upi_id"
        assert "value" not in upi_entity
        assert "valueHash" in upi_entity
        assert upi_entity["partialValue"] == "****@paytm"
        assert upi_entity["confidence"] == 0.95
        assert "context" not in upi_entity
        assert upi_entity["contextLength"] == len("Send money to scammer@paytm now")
        
        # Check phone entity
        phone_entity = sanitized_entities[1]
        assert phone_entity["type"] == "phone_number"
        assert "value" not in phone_entity
        assert "valueHash" in phone_entity
        assert phone_entity["partialValue"] == "98****10"
        assert phone_entity["verified"] is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])