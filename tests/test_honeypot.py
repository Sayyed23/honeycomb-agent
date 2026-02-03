"""
Tests for the honeypot API endpoint.
"""

import pytest
from fastapi.testclient import TestClient
from datetime import datetime

from app.main import app
from config.settings import settings

client = TestClient(app)


def test_honeypot_endpoint_requires_auth():
    """Test that honeypot endpoint requires authentication."""
    response = client.post("/api/honeypot", json={})
    assert response.status_code == 401
    
    data = response.json()
    assert "Missing x-api-key header" in data["detail"]


def test_honeypot_endpoint_invalid_auth():
    """Test that honeypot endpoint rejects invalid API keys."""
    response = client.post(
        "/api/honeypot",
        json={},
        headers={"x-api-key": "invalid-key"}
    )
    assert response.status_code == 403
    
    data = response.json()
    assert "Invalid API key" in data["detail"]


def test_honeypot_endpoint_valid_request():
    """Test that honeypot endpoint processes valid requests."""
    request_data = {
        "sessionId": "test-session-001",
        "message": "Hello, this is a test message",
        "conversationHistory": [],
        "metadata": {
            "language": "en"
        }
    }
    
    response = client.post(
        "/api/honeypot",
        json=request_data,
        headers={"x-api-key": settings.api_key_secret}
    )
    
    assert response.status_code == 200
    
    data = response.json()
    assert data["status"] == "success"
    assert data["sessionId"] == "test-session-001"
    assert "reply" in data
    assert "timestamp" in data
    assert len(data["reply"]) > 0


def test_honeypot_endpoint_invalid_session_id():
    """Test that honeypot endpoint validates session ID format."""
    request_data = {
        "sessionId": "invalid session id with spaces!",
        "message": "Test message",
        "conversationHistory": []
    }
    
    response = client.post(
        "/api/honeypot",
        json=request_data,
        headers={"x-api-key": settings.api_key_secret}
    )
    
    assert response.status_code == 422  # Validation error


def test_honeypot_endpoint_empty_message():
    """Test that honeypot endpoint rejects empty messages."""
    request_data = {
        "sessionId": "test-session-002",
        "message": "",
        "conversationHistory": []
    }
    
    response = client.post(
        "/api/honeypot",
        json=request_data,
        headers={"x-api-key": settings.api_key_secret}
    )
    
    assert response.status_code == 422  # Validation error


def test_honeypot_endpoint_with_conversation_history():
    """Test that honeypot endpoint handles conversation history."""
    request_data = {
        "sessionId": "test-session-003",
        "message": "This is a follow-up message",
        "conversationHistory": [
            {
                "role": "user",
                "content": "Previous user message",
                "timestamp": "2024-01-01T12:00:00Z"
            },
            {
                "role": "assistant",
                "content": "Previous assistant response",
                "timestamp": "2024-01-01T12:01:00Z"
            }
        ],
        "metadata": {
            "language": "en",
            "userAgent": "Test Agent"
        }
    }
    
    response = client.post(
        "/api/honeypot",
        json=request_data,
        headers={"x-api-key": settings.api_key_secret}
    )
    
    assert response.status_code == 200
    
    data = response.json()
    assert data["status"] == "success"
    assert data["sessionId"] == "test-session-003"


def test_honeypot_endpoint_invalid_language():
    """Test that honeypot endpoint validates language codes."""
    request_data = {
        "sessionId": "test-session-004",
        "message": "Test message",
        "conversationHistory": [],
        "metadata": {
            "language": "invalid-lang"
        }
    }
    
    response = client.post(
        "/api/honeypot",
        json=request_data,
        headers={"x-api-key": settings.api_key_secret}
    )
    
    assert response.status_code == 422  # Validation error