"""
Integration tests for the honeypot API with authentication.
"""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import Mock, patch
from datetime import datetime

from app.main import app
from app.core.auth import APIKeyManager
from app.database.models import APIKey


class TestHoneypotAPIIntegration:
    """Integration tests for the honeypot API."""
    
    def setup_method(self):
        """Set up test client."""
        self.client = TestClient(app)
        
        # Create a test API key
        self.test_api_key = "test-api-key-12345"
        self.key_hash = APIKeyManager.hash_api_key(self.test_api_key)
        self.key_prefix = APIKeyManager.get_key_prefix(self.test_api_key)
        
        # Mock API key record
        self.mock_api_key = APIKey(
            key_name="Test Key",
            key_hash=self.key_hash,
            key_prefix=self.key_prefix,
            is_active=True,
            expires_at=None,
            rate_limit_per_hour=1000,
            current_hour_usage=0,
            current_hour_start=datetime.utcnow().replace(minute=0, second=0, microsecond=0)
        )
    
    def test_honeypot_endpoint_without_api_key(self):
        """Test honeypot endpoint without API key."""
        payload = {
            "sessionId": "test-session-001",
            "message": "Hello, this is a test message",
            "conversationHistory": [],
            "metadata": {"language": "en"}
        }
        
        response = self.client.post("/api/honeypot", json=payload)
        
        assert response.status_code == 401
        assert "Missing x-api-key header" in response.json()["detail"]
    
    def test_honeypot_endpoint_with_invalid_api_key(self):
        """Test honeypot endpoint with invalid API key."""
        payload = {
            "sessionId": "test-session-001",
            "message": "Hello, this is a test message",
            "conversationHistory": [],
            "metadata": {"language": "en"}
        }
        
        headers = {"x-api-key": "invalid-key"}
        
        with patch('app.core.auth.APIKeyManager.validate_api_key') as mock_validate:
            mock_validate.return_value = None
            
            response = self.client.post("/api/honeypot", json=payload, headers=headers)
        
        assert response.status_code == 403
        assert "Invalid or expired API key" in response.json()["detail"]
    
    @patch('app.core.auth.APIKeyManager.record_api_usage')
    @patch('app.core.auth.APIKeyManager.check_rate_limit')
    @patch('app.core.auth.APIKeyManager.validate_api_key')
    def test_honeypot_endpoint_with_valid_api_key(self, mock_validate, mock_rate_limit, mock_record_usage):
        """Test honeypot endpoint with valid API key."""
        # Mock successful validation
        mock_validate.return_value = self.mock_api_key
        mock_rate_limit.return_value = True
        mock_record_usage.return_value = None
        
        payload = {
            "sessionId": "test-session-001",
            "message": "Hello, this is a test message",
            "conversationHistory": [],
            "metadata": {"language": "en"}
        }
        
        headers = {
            "x-api-key": self.test_api_key,
            "content-type": "application/json"
        }
        
        response = self.client.post("/api/honeypot", json=payload, headers=headers)
        
        assert response.status_code == 200
        
        response_data = response.json()
        assert response_data["status"] == "success"
        assert response_data["sessionId"] == "test-session-001"
        assert "reply" in response_data
        assert "timestamp" in response_data
        
        # Check security headers
        assert "X-Content-Type-Options" in response.headers
        assert "X-Frame-Options" in response.headers
        assert "X-XSS-Protection" in response.headers
        
        # Check rate limit headers
        assert "X-RateLimit-Limit" in response.headers
        assert "X-RateLimit-Remaining" in response.headers
        assert "X-RateLimit-Reset" in response.headers
    
    def test_honeypot_endpoint_invalid_json(self):
        """Test honeypot endpoint with invalid JSON."""
        headers = {"x-api-key": self.test_api_key}
        
        with patch('app.core.auth.APIKeyManager.validate_api_key') as mock_validate:
            mock_validate.return_value = self.mock_api_key
            
            # Send invalid JSON
            response = self.client.post(
                "/api/honeypot", 
                data="invalid json", 
                headers=headers
            )
        
        assert response.status_code == 422  # FastAPI validation error    
    def test_honeypot_endpoint_missing_required_fields(self):
        """Test honeypot endpoint with missing required fields."""
        payload = {
            "message": "Hello, this is a test message"
            # Missing sessionId
        }
        
        headers = {
            "x-api-key": self.test_api_key,
            "content-type": "application/json"
        }
        
        with patch('app.core.auth.APIKeyManager.validate_api_key') as mock_validate:
            mock_validate.return_value = self.mock_api_key
            
            response = self.client.post("/api/honeypot", json=payload, headers=headers)
        
        assert response.status_code == 422  # FastAPI validation error
    
    @patch('app.core.auth.APIKeyManager.record_api_usage')
    @patch('app.core.auth.APIKeyManager.check_rate_limit')
    @patch('app.core.auth.APIKeyManager.validate_api_key')
    def test_honeypot_endpoint_with_conversation_history(self, mock_validate, mock_rate_limit, mock_record_usage):
        """Test honeypot endpoint with conversation history."""
        # Mock successful validation
        mock_validate.return_value = self.mock_api_key
        mock_rate_limit.return_value = True
        mock_record_usage.return_value = None
        
        payload = {
            "sessionId": "test-session-002",
            "message": "This is my second message",
            "conversationHistory": [
                {
                    "role": "user",
                    "content": "Hello, this is my first message",
                    "timestamp": "2024-01-01T10:00:00Z"
                },
                {
                    "role": "assistant",
                    "content": "Thank you for your message.",
                    "timestamp": "2024-01-01T10:00:01Z"
                }
            ],
            "metadata": {
                "language": "en",
                "userAgent": "TestClient/1.0",
                "platform": "test"
            }
        }
        
        headers = {
            "x-api-key": self.test_api_key,
            "content-type": "application/json"
        }
        
        response = self.client.post("/api/honeypot", json=payload, headers=headers)
        
        assert response.status_code == 200
        
        response_data = response.json()
        assert response_data["status"] == "success"
        assert response_data["sessionId"] == "test-session-002"
    
    def test_health_endpoint_no_auth_required(self):
        """Test that health endpoint doesn't require authentication."""
        response = self.client.get("/health")
        
        # Should work without API key
        assert response.status_code == 200
        
        response_data = response.json()
        assert "status" in response_data
        assert "timestamp" in response_data
        assert "version" in response_data
        assert "components" in response_data
        assert "metrics" in response_data