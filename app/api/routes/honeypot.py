"""
Main honeypot API endpoint for scam detection and agent interaction.
"""

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from datetime import datetime
from typing import List, Optional, Dict, Any
import uuid

from config.settings import settings
from app.core.logging import get_logger, ContextLogger
from app.core.metrics import MetricsCollector

logger = get_logger(__name__)

router = APIRouter()


class ConversationMessage(BaseModel):
    """Individual conversation message model."""
    role: str = Field(..., description="Message role: 'user' or 'assistant'")
    content: str = Field(..., min_length=1, max_length=5000, description="Message content")
    timestamp: datetime = Field(..., description="Message timestamp")
    
    @field_validator("role")
    @classmethod
    def validate_role(cls, v):
        if v not in ["user", "assistant"]:
            raise ValueError("Role must be 'user' or 'assistant'")
        return v


class MessageMetadata(BaseModel):
    """Optional metadata for the message."""
    userAgent: Optional[str] = Field(None, max_length=500, description="User agent string")
    ipAddress: Optional[str] = Field(None, max_length=45, description="IP address")
    platform: Optional[str] = Field(None, max_length=100, description="Platform information")
    language: Optional[str] = Field("en", description="Message language")
    
    @field_validator("language")
    @classmethod
    def validate_language(cls, v):
        allowed_languages = ["en", "hi", "hinglish"]
        if v not in allowed_languages:
            raise ValueError(f"Language must be one of: {allowed_languages}")
        return v


class HoneypotRequest(BaseModel):
    """Request model for the honeypot API endpoint."""
    sessionId: str = Field(..., min_length=1, max_length=100, description="Unique session identifier")
    message: str = Field(..., min_length=1, max_length=5000, description="Message content to analyze")
    conversationHistory: List[ConversationMessage] = Field(
        default_factory=list,
        max_length=50,
        description="Previous conversation messages"
    )
    metadata: Optional[MessageMetadata] = Field(None, description="Optional message metadata")
    
    @field_validator("sessionId")
    @classmethod
    def validate_session_id(cls, v):
        # Allow alphanumeric characters, hyphens, and underscores
        import re
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError("Session ID must contain only alphanumeric characters, hyphens, and underscores")
        return v
    
    @field_validator("conversationHistory")
    @classmethod
    def validate_conversation_history(cls, v):
        if len(v) > 50:
            raise ValueError("Conversation history cannot exceed 50 messages")
        
        # Ensure chronological order
        for i in range(1, len(v)):
            if v[i].timestamp < v[i-1].timestamp:
                raise ValueError("Conversation history must be in chronological order")
        
        return v


class HoneypotResponse(BaseModel):
    """Response model for the honeypot API endpoint."""
    status: str = Field(..., description="Response status: 'success' or 'error'")
    reply: str = Field(..., min_length=1, max_length=2000, description="System response message")
    sessionId: str = Field(..., description="Session identifier")
    timestamp: datetime = Field(..., description="Response timestamp")
    error: Optional[str] = Field(None, description="Error message if status is 'error'")


async def validate_api_key(request: Request) -> str:
    """
    Validate API key from request headers.
    
    Args:
        request: FastAPI request object
        
    Returns:
        str: Validated API key
        
    Raises:
        HTTPException: If API key is missing or invalid
    """
    api_key = request.headers.get("x-api-key")
    
    if not api_key:
        logger.warning(
            "API request without API key",
            extra={
                "client_ip": request.client.host if request.client else None,
                "user_agent": request.headers.get("user-agent"),
                "endpoint": str(request.url)
            }
        )
        raise HTTPException(
            status_code=401,
            detail="Missing x-api-key header"
        )
    
    # TODO: Implement actual API key validation against database
    # For now, check against a simple secret
    if api_key != settings.api_key_secret:
        logger.warning(
            "API request with invalid API key",
            extra={
                "client_ip": request.client.host if request.client else None,
                "user_agent": request.headers.get("user-agent"),
                "endpoint": str(request.url),
                "provided_key": api_key[:8] + "..." if len(api_key) > 8 else api_key
            }
        )
        raise HTTPException(
            status_code=403,
            detail="Invalid API key"
        )
    
    return api_key


def sanitize_input(text: str) -> str:
    """
    Sanitize input text to prevent XSS and other attacks.
    
    Args:
        text: Input text to sanitize
        
    Returns:
        str: Sanitized text
    """
    # Basic sanitization - remove potentially dangerous characters
    import html
    import re
    
    # HTML escape
    sanitized = html.escape(text)
    
    # Remove potential script tags and other dangerous patterns
    dangerous_patterns = [
        r'<script[^>]*>.*?</script>',
        r'javascript:',
        r'vbscript:',
        r'onload=',
        r'onerror=',
        r'onclick=',
    ]
    
    for pattern in dangerous_patterns:
        sanitized = re.sub(pattern, '', sanitized, flags=re.IGNORECASE | re.DOTALL)
    
    return sanitized.strip()


@router.post("/honeypot", response_model=HoneypotResponse)
async def process_honeypot_message(
    request_data: HoneypotRequest,
    request: Request,
    api_key: str = Depends(validate_api_key)
):
    """
    Main honeypot endpoint for processing potential scam messages.
    
    This endpoint:
    1. Validates the incoming message and metadata
    2. Analyzes the message for scam indicators
    3. Decides whether to activate an AI agent
    4. Returns an appropriate response
    
    Args:
        request_data: The honeypot request containing message and metadata
        request: FastAPI request object
        api_key: Validated API key from dependency
        
    Returns:
        HoneypotResponse: Response containing reply and metadata
    """
    correlation_id = getattr(request.state, "correlation_id", str(uuid.uuid4()))
    context_logger = ContextLogger(logger, {
        "correlation_id": correlation_id,
        "session_id": request_data.sessionId
    })
    
    try:
        context_logger.info(
            "Processing honeypot message",
            extra={
                "message_length": len(request_data.message),
                "history_length": len(request_data.conversationHistory),
                "language": request_data.metadata.language if request_data.metadata else "en",
                "client_ip": request.client.host if request.client else None
            }
        )
        
        # Sanitize input message
        sanitized_message = sanitize_input(request_data.message)
        
        # TODO: Implement actual scam detection logic
        # For now, return a simple non-engaging response
        risk_score = 0.3  # Placeholder
        confidence = 0.8  # Placeholder
        
        # Record metrics
        MetricsCollector.record_scam_detection(
            result="no_scam_detected",
            confidence=confidence,
            risk_score=risk_score
        )
        
        # Generate response
        response_message = "Thank you for your message. I'll get back to you soon."
        
        context_logger.info(
            "Honeypot message processed successfully",
            extra={
                "risk_score": risk_score,
                "confidence": confidence,
                "response_length": len(response_message)
            }
        )
        
        return HoneypotResponse(
            status="success",
            reply=response_message,
            sessionId=request_data.sessionId,
            timestamp=datetime.utcnow()
        )
        
    except ValueError as e:
        context_logger.warning(f"Validation error: {e}")
        raise HTTPException(status_code=400, detail=str(e))
        
    except Exception as e:
        context_logger.error(f"Unexpected error processing honeypot message: {e}", exc_info=True)
        
        return HoneypotResponse(
            status="error",
            reply="I'm sorry, I'm having trouble processing your message right now. Please try again later.",
            sessionId=request_data.sessionId,
            timestamp=datetime.utcnow(),
            error="Internal processing error"
        )