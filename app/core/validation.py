"""
Request validation and sanitization utilities.
"""

import re
import html
import json
from typing import Any, Dict, List, Optional, Union
from fastapi import HTTPException
from pydantic import BaseModel, ValidationError

from app.core.logging import get_logger

logger = get_logger(__name__)


class InputSanitizer:
    """Utility class for input sanitization and validation."""
    
    # Dangerous patterns that should be removed or escaped
    DANGEROUS_PATTERNS = [
        r'<script[^>]*>.*?</script>',  # Script tags
        r'javascript:',               # JavaScript URLs
        r'vbscript:',                # VBScript URLs
        r'data:text/html',           # Data URLs with HTML
        r'onload\s*=',               # Event handlers
        r'onerror\s*=',
        r'onclick\s*=',
        r'onmouseover\s*=',
        r'onfocus\s*=',
        r'onblur\s*=',
        r'onchange\s*=',
        r'onsubmit\s*=',
        r'<iframe[^>]*>.*?</iframe>', # Iframe tags
        r'<object[^>]*>.*?</object>', # Object tags
        r'<embed[^>]*>.*?</embed>',   # Embed tags
        r'<link[^>]*>',               # Link tags
        r'<meta[^>]*>',               # Meta tags
        r'<style[^>]*>.*?</style>',   # Style tags
    ]
    
    # SQL injection patterns
    SQL_INJECTION_PATTERNS = [
        r"';\s*drop\s+table",
        r"';\s*delete\s+from",
        r"';\s*update\s+",
        r"';\s*insert\s+into",
        r"union\s+select",
        r"'.*or.*'.*=.*'",
        r"'.*and.*'.*=.*'",
        r"--",
        r"/\*.*\*/",
    ]
    
    # Command injection patterns
    COMMAND_INJECTION_PATTERNS = [
        r";\s*rm\s+",
        r";\s*cat\s+",
        r";\s*ls\s+",
        r";\s*pwd",
        r";\s*whoami",
        r";\s*id",
        r"\|\s*nc\s+",
        r"\|\s*netcat\s+",
        r"&&\s*",
        r"\|\|\s*",
        r"`.*`",
        r"\$\(.*\)",
    ]
    
    @classmethod
    def sanitize_text(cls, text: str, max_length: Optional[int] = None) -> str:
        """
        Sanitize text input to prevent XSS and other attacks.
        
        Args:
            text: Input text to sanitize
            max_length: Maximum allowed length
            
        Returns:
            str: Sanitized text
            
        Raises:
            ValueError: If text is too long or contains dangerous patterns
        """
        if not isinstance(text, str):
            raise ValueError("Input must be a string")
        
        # Check length
        if max_length and len(text) > max_length:
            raise ValueError(f"Text too long: {len(text)} > {max_length}")
        
        # HTML escape first
        sanitized = html.escape(text)
        
        # Remove dangerous patterns
        for pattern in cls.DANGEROUS_PATTERNS:
            sanitized = re.sub(pattern, '', sanitized, flags=re.IGNORECASE | re.DOTALL)
        
        # Check for SQL injection attempts
        for pattern in cls.SQL_INJECTION_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                logger.warning(
                    "SQL injection attempt detected",
                    extra={"pattern": pattern, "text_length": len(text)}
                )
                raise ValueError("Potentially malicious input detected")
        
        # Check for command injection attempts
        for pattern in cls.COMMAND_INJECTION_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                logger.warning(
                    "Command injection attempt detected",
                    extra={"pattern": pattern, "text_length": len(text)}
                )
                raise ValueError("Potentially malicious input detected")
        
        return sanitized.strip()
    
    @classmethod
    def sanitize_session_id(cls, session_id: str) -> str:
        """
        Sanitize and validate session ID.
        
        Args:
            session_id: Session ID to validate
            
        Returns:
            str: Sanitized session ID
            
        Raises:
            ValueError: If session ID is invalid
        """
        if not isinstance(session_id, str):
            raise ValueError("Session ID must be a string")
        
        if not session_id.strip():
            raise ValueError("Session ID cannot be empty")
        
        if len(session_id) > 100:
            raise ValueError("Session ID too long")
        
        # Allow only alphanumeric characters, hyphens, and underscores
        if not re.match(r'^[a-zA-Z0-9_-]+$', session_id):
            raise ValueError("Session ID contains invalid characters")
        
        return session_id.strip()
    
    @classmethod
    def validate_language(cls, language: str) -> str:
        """
        Validate language code.
        
        Args:
            language: Language code to validate
            
        Returns:
            str: Validated language code
            
        Raises:
            ValueError: If language code is invalid
        """
        allowed_languages = ["en", "hi", "hinglish"]
        
        if language not in allowed_languages:
            raise ValueError(f"Language must be one of: {allowed_languages}")
        
        return language
    
    @classmethod
    def validate_ip_address(cls, ip_address: str) -> bool:
        """
        Validate IP address format.
        
        Args:
            ip_address: IP address to validate
            
        Returns:
            bool: True if valid IP address
        """
        # IPv4 pattern - more strict validation
        ipv4_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$'
        
        # IPv6 pattern (simplified but more accurate)
        ipv6_pattern = r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$'
        
        return bool(re.match(ipv4_pattern, ip_address) or re.match(ipv6_pattern, ip_address))
    
    @classmethod
    def sanitize_metadata(cls, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize metadata dictionary.
        
        Args:
            metadata: Metadata dictionary to sanitize
            
        Returns:
            Dict[str, Any]: Sanitized metadata
        """
        if not isinstance(metadata, dict):
            raise ValueError("Metadata must be a dictionary")
        
        sanitized = {}
        
        for key, value in metadata.items():
            # Sanitize key
            if not isinstance(key, str):
                continue
            
            sanitized_key = cls.sanitize_text(key, max_length=100)
            
            # Sanitize value based on type
            if isinstance(value, str):
                sanitized_value = cls.sanitize_text(value, max_length=1000)
            elif isinstance(value, (int, float, bool)):
                sanitized_value = value
            elif value is None:
                sanitized_value = None
            else:
                # Convert other types to string and sanitize
                sanitized_value = cls.sanitize_text(str(value), max_length=1000)
            
            sanitized[sanitized_key] = sanitized_value
        
        return sanitized


class RequestValidator:
    """Utility class for request validation."""
    
    @staticmethod
    def validate_json_payload(payload: str, max_size: int = 1024 * 1024) -> Dict[str, Any]:
        """
        Validate and parse JSON payload.
        
        Args:
            payload: JSON string to validate
            max_size: Maximum payload size in bytes
            
        Returns:
            Dict[str, Any]: Parsed JSON data
            
        Raises:
            HTTPException: If JSON is invalid or too large
        """
        if len(payload.encode('utf-8')) > max_size:
            raise HTTPException(
                status_code=413,
                detail=f"Request payload too large: {len(payload)} bytes > {max_size} bytes"
            )
        
        try:
            return json.loads(payload)
        except json.JSONDecodeError as e:
            logger.warning(f"Invalid JSON payload: {e}")
            raise HTTPException(
                status_code=400,
                detail="Invalid JSON format"
            )
    
    @staticmethod
    def validate_content_type(content_type: Optional[str]) -> None:
        """
        Validate request content type.
        
        Args:
            content_type: Content type header value
            
        Raises:
            HTTPException: If content type is invalid
        """
        if not content_type:
            raise HTTPException(
                status_code=400,
                detail="Missing Content-Type header"
            )
        
        allowed_types = [
            "application/json",
            "application/json; charset=utf-8"
        ]
        
        if content_type.lower() not in [t.lower() for t in allowed_types]:
            raise HTTPException(
                status_code=415,
                detail=f"Unsupported Content-Type: {content_type}"
            )
    
    @staticmethod
    def validate_user_agent(user_agent: Optional[str]) -> Optional[str]:
        """
        Validate and sanitize user agent string.
        
        Args:
            user_agent: User agent string
            
        Returns:
            Optional[str]: Sanitized user agent or None
        """
        if not user_agent:
            return None
        
        # Limit user agent length
        if len(user_agent) > 500:
            user_agent = user_agent[:500]
        
        # Basic sanitization
        return InputSanitizer.sanitize_text(user_agent, max_length=500)
    
    @staticmethod
    def validate_pydantic_model(model_class: type, data: Dict[str, Any]) -> BaseModel:
        """
        Validate data against a Pydantic model.
        
        Args:
            model_class: Pydantic model class
            data: Data to validate
            
        Returns:
            BaseModel: Validated model instance
            
        Raises:
            HTTPException: If validation fails
        """
        try:
            return model_class(**data)
        except ValidationError as e:
            logger.warning(f"Pydantic validation error: {e}")
            
            # Format validation errors for user-friendly response
            errors = []
            for error in e.errors():
                field = " -> ".join(str(loc) for loc in error["loc"])
                message = error["msg"]
                errors.append(f"{field}: {message}")
            
            raise HTTPException(
                status_code=400,
                detail={
                    "message": "Validation error",
                    "errors": errors
                }
            )


class SecurityHeaders:
    """Utility class for security headers."""
    
    @staticmethod
    def get_security_headers() -> Dict[str, str]:
        """
        Get standard security headers.
        
        Returns:
            Dict[str, str]: Security headers
        """
        return {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Content-Security-Policy": "default-src 'self'; script-src 'none'; object-src 'none';",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()"
        }
    
    @staticmethod
    def get_cors_headers() -> Dict[str, str]:
        """
        Get CORS headers for API responses.
        
        Returns:
            Dict[str, str]: CORS headers
        """
        return {
            "Access-Control-Allow-Origin": "https://hackathon.guvi.in",
            "Access-Control-Allow-Methods": "GET, POST",
            "Access-Control-Allow-Headers": "x-api-key, content-type",
            "Access-Control-Max-Age": "86400"
        }