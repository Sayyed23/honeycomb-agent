"""
Main honeypot API endpoint for scam detection and agent interaction.
"""

import time
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field, field_validator
from datetime import datetime
from typing import List, Optional, Dict, Any
import uuid

from config.settings import settings
from app.core.logging import get_logger, ContextLogger
from app.core.metrics import MetricsCollector
from app.core.auth import validate_api_key_dependency, APIKeyManager, RateLimiter
from app.core.validation import InputSanitizer, RequestValidator, SecurityHeaders
from app.core.scam_detection import ScamDetectionEngine, LanguageDetector
from app.core.agent_activation import agent_activation_engine, ActivationDecision, PersonaType
from app.core.conversation_engine import conversation_engine
from app.core.entity_extraction import entity_extraction_engine
from app.database.models import APIKey, Session as DBSession, Message, RiskAssessment
from app.database.connection import get_db
from app.database.utils import DatabaseManager
from sqlalchemy.orm import Session

logger = get_logger(__name__)

router = APIRouter()

# Initialize scam detection engine
scam_detector = ScamDetectionEngine()


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
    
    @field_validator("content")
    @classmethod
    def validate_content(cls, v):
        # Sanitize content
        return InputSanitizer.sanitize_text(v, max_length=5000)


class MessageMetadata(BaseModel):
    """Optional metadata for the message."""
    userAgent: Optional[str] = Field(None, max_length=500, description="User agent string")
    ipAddress: Optional[str] = Field(None, max_length=45, description="IP address")
    platform: Optional[str] = Field(None, max_length=100, description="Platform information")
    language: Optional[str] = Field("en", description="Message language")
    
    @field_validator("language")
    @classmethod
    def validate_language(cls, v):
        return InputSanitizer.validate_language(v)
    
    @field_validator("userAgent")
    @classmethod
    def validate_user_agent(cls, v):
        if v is None:
            return v
        return InputSanitizer.sanitize_text(v, max_length=500)
    
    @field_validator("platform")
    @classmethod
    def validate_platform(cls, v):
        if v is None:
            return v
        return InputSanitizer.sanitize_text(v, max_length=100)
    
    @field_validator("ipAddress")
    @classmethod
    def validate_ip_address(cls, v):
        if v is None:
            return v
        if not InputSanitizer.validate_ip_address(v):
            raise ValueError("Invalid IP address format")
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
        return InputSanitizer.sanitize_session_id(v)
    
    @field_validator("message")
    @classmethod
    def validate_message(cls, v):
        return InputSanitizer.sanitize_text(v, max_length=5000)
    
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


@router.post("/honeypot", response_model=HoneypotResponse)
async def process_honeypot_message(
    request_data: HoneypotRequest,
    request: Request,
    response: Response,
    api_key_record: APIKey = Depends(validate_api_key_dependency),
    db: Session = Depends(get_db)
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
        response: FastAPI response object
        api_key_record: Validated API key record from dependency
        db: Database session
        
    Returns:
        HoneypotResponse: Response containing reply and metadata
    """
    start_time = time.time()
    correlation_id = getattr(request.state, "correlation_id", str(uuid.uuid4()))
    context_logger = ContextLogger(logger, {
        "correlation_id": correlation_id,
        "session_id": request_data.sessionId,
        "api_key_name": api_key_record.key_name
    })
    
    try:
        # Add security headers
        security_headers = SecurityHeaders.get_security_headers()
        for header_name, header_value in security_headers.items():
            response.headers[header_name] = header_value
        
        # Add rate limit headers
        rate_limit_headers = RateLimiter.get_rate_limit_headers(api_key_record)
        for header_name, header_value in rate_limit_headers.items():
            response.headers[header_name] = header_value
        
        context_logger.info(
            "Processing honeypot message",
            extra={
                "message_length": len(request_data.message),
                "history_length": len(request_data.conversationHistory),
                "language": request_data.metadata.language if request_data.metadata else "en",
                "client_ip": request.client.host if request.client else None,
                "user_agent": request.headers.get("user-agent")
            }
        )
        
        # Validate content type
        content_type = request.headers.get("content-type")
        RequestValidator.validate_content_type(content_type)
        
        # Detect and validate language
        detected_language = LanguageDetector.detect_language(request_data.message)
        final_language = request_data.metadata.language if request_data.metadata else detected_language
        
        # Ensure language is supported
        if not LanguageDetector.is_supported_language(final_language):
            context_logger.warning(f"Unsupported language detected: {final_language}")
            final_language = 'en'  # Default to English
        
        context_logger.info(
            "Language detection completed",
            extra={
                "detected_language": detected_language,
                "requested_language": request_data.metadata.language if request_data.metadata else None,
                "final_language": final_language
            }
        )
        
        # Prepare conversation history for analysis
        conversation_history = []
        for msg in request_data.conversationHistory:
            conversation_history.append({
                "role": msg.role,
                "content": msg.content,
                "timestamp": msg.timestamp.isoformat()
            })
        
        # Prepare metadata for analysis
        analysis_metadata = {
            "language": final_language,
            "user_agent": request_data.metadata.userAgent if request_data.metadata else None,
            "ip_address": request_data.metadata.ipAddress if request_data.metadata else None,
            "platform": request_data.metadata.platform if request_data.metadata else None,
            "client_ip": request.client.host if request.client else None,
            "request_headers": dict(request.headers),
            "session_id": request_data.sessionId,
            "correlation_id": correlation_id
        }
        
        # Perform scam detection analysis
        context_logger.info("Starting scam detection analysis")
        risk_score, confidence = scam_detector.calculate_risk_score(
            message=request_data.message,
            conversation_history=conversation_history,
            metadata=analysis_metadata
        )
        
        context_logger.info(
            "Scam detection analysis completed",
            extra={
                "risk_score": risk_score,
                "confidence": confidence,
                "is_high_risk": risk_score >= 0.75
            }
        )
        
        # Initialize database manager
        db_manager = DatabaseManager(db)
        
        # Create or get existing session
        try:
            db_session = db_manager.get_session_by_id(request_data.sessionId)
            if not db_session:
                # Create new session
                db_session = db_manager.create_session(
                    session_id=request_data.sessionId,
                    risk_score=risk_score,
                    confidence_level=confidence
                )
                context_logger.info(f"Created new session: {request_data.sessionId}")
            else:
                # Update existing session with new risk score if higher
                if risk_score > db_session.risk_score:
                    db_session.risk_score = risk_score
                    db_session.confidence_level = confidence
                    db.commit()
                    context_logger.info(f"Updated session risk score: {risk_score}")
        except Exception as e:
            context_logger.error(f"Error managing session: {e}", exc_info=True)
            # Continue without database session if there's an error
            db_session = None
        
        # Store the incoming message
        try:
            if db_session:
                message_record = Message(
                    session_id=db_session.id,
                    role="user",
                    content=request_data.message,
                    language=final_language,
                    timestamp=datetime.utcnow(),
                    metadata={
                        "user_agent": analysis_metadata.get("user_agent"),
                        "ip_address": analysis_metadata.get("ip_address"),
                        "platform": analysis_metadata.get("platform")
                    }
                )
                db.add(message_record)
                db.commit()
                db.refresh(message_record)
                
                # Store risk assessment
                risk_assessment = RiskAssessment(
                    session_id=db_session.id,
                    message_id=message_record.id,
                    risk_score=risk_score,
                    confidence=confidence,
                    detection_method="combined_analysis",
                    risk_factors={}  # Will be populated by detailed analysis later
                )
                db.add(risk_assessment)
                db.commit()
                
                context_logger.info("Stored message and risk assessment in database")
        except Exception as e:
            context_logger.error(f"Error storing message data: {e}", exc_info=True)
        
        # Generate appropriate response based on risk score and agent activation
        if risk_score >= 0.75:
            # High risk - check if agent should be activated
            context_logger.info("High risk detected, evaluating agent activation")
            
            activation_result = await agent_activation_engine.should_activate_agent(
                session_id=request_data.sessionId,
                risk_score=risk_score,
                confidence=confidence,
                message_content=request_data.message,
                conversation_history=conversation_history,
                metadata=analysis_metadata
            )
            
            if activation_result.decision == ActivationDecision.ACTIVATE:
                # Agent activated - update session state
                if db_session:
                    try:
                        from app.core.session_manager import session_manager
                        await session_manager.activate_agent(
                            request_data.sessionId, 
                            activation_result.persona.value
                        )
                        context_logger.info(
                            f"Agent activated with persona: {activation_result.persona.value}",
                            extra={
                                "persona": activation_result.persona.value,
                                "activation_probability": activation_result.probability_used,
                                "reasoning": activation_result.reasoning[:3]  # First 3 reasons
                            }
                        )
                    except Exception as e:
                        context_logger.error(f"Error updating session with agent activation: {e}")
                
                # Generate persona-based response using conversation engine
                try:
                    response_result = await conversation_engine.generate_response(
                        session_id=request_data.sessionId,
                        message_content=request_data.message,
                        conversation_history=conversation_history,
                        metadata=analysis_metadata
                    )
                    response_message = response_result.response_content
                    
                    context_logger.info(
                        "Generated persona-based response",
                        extra={
                            "persona": activation_result.persona.value,
                            "consistency_score": response_result.persona_consistency_score,
                            "response_length": len(response_message),
                            "generation_method": response_result.generation_method
                        }
                    )
                    
                    # Extract entities from the conversation (user message + response)
                    try:
                        full_conversation_text = request_data.message + " " + response_message
                        extraction_result = await entity_extraction_engine.extract_entities(
                            text=full_conversation_text,
                            session_id=request_data.sessionId,
                            context=f"Conversation turn {len(conversation_history) + 1}",
                            confidence_threshold=0.8
                        )
                        
                        context_logger.info(
                            "Entity extraction completed",
                            extra={
                                "entities_extracted": extraction_result.high_confidence_count,
                                "total_candidates": extraction_result.total_candidates,
                                "processing_time_ms": extraction_result.processing_time_ms,
                                "extraction_accuracy": extraction_result.extraction_summary.get('extraction_accuracy', 0)
                            }
                        )
                        
                    except Exception as e:
                        context_logger.error(f"Error during entity extraction: {e}", exc_info=True)
                        # Continue without entity extraction if there's an error
                    
                except Exception as e:
                    context_logger.error(f"Error generating persona response: {e}", exc_info=True)
                    # Fallback to placeholder response
                    response_message = _generate_agent_placeholder_response(
                        final_language, 
                        activation_result.persona,
                        risk_score
                    )
                    context_logger.info("Used fallback placeholder response due to generation error")
            else:
                # Agent not activated - use non-engaging response
                response_message = activation_result.response_template
                context_logger.info(
                    "Agent not activated, using non-engaging response",
                    extra={
                        "probability_used": activation_result.probability_used,
                        "reasoning": activation_result.reasoning[:2]  # First 2 reasons
                    }
                )
                
                # Still extract entities from high-risk messages for intelligence
                try:
                    extraction_result = await entity_extraction_engine.extract_entities(
                        text=request_data.message,
                        session_id=request_data.sessionId,
                        context="High-risk message without agent activation",
                        confidence_threshold=0.9  # Higher threshold for non-agent messages
                    )
                    
                    context_logger.info(
                        "Entity extraction completed for high-risk non-agent message",
                        extra={
                            "entities_extracted": extraction_result.high_confidence_count,
                            "total_candidates": extraction_result.total_candidates
                        }
                    )
                    
                except Exception as e:
                    context_logger.error(f"Error during entity extraction: {e}", exc_info=True)
        elif risk_score >= 0.5:
            # Medium risk - cautious response
            response_message = _generate_medium_risk_response(final_language)
            context_logger.info("Generated medium-risk response")
        else:
            # Low risk - standard response
            response_message = _generate_low_risk_response(final_language)
            context_logger.info("Generated low-risk response")
        
        # Store the response message
        try:
            if db_session:
                response_record = Message(
                    session_id=db_session.id,
                    role="assistant",
                    content=response_message,
                    language=final_language,
                    timestamp=datetime.utcnow(),
                    metadata={"response_type": "automated", "risk_based": True}
                )
                db.add(response_record)
                
                # Update session turn count
                db_session.total_turns += 1
                db.commit()
        except Exception as e:
            context_logger.error(f"Error storing response message: {e}", exc_info=True)
        
        # Record metrics
        MetricsCollector.record_scam_detection(
            result="scam_detected" if risk_score >= 0.75 else "no_scam_detected",
            confidence=confidence,
            risk_score=risk_score
        )
        # Calculate response time
        response_time_ms = int((time.time() - start_time) * 1000)
        
        # Record API usage
        await APIKeyManager.record_api_usage(
            db=db,
            api_key_record=api_key_record,
            request=request,
            status_code=200,
            response_time_ms=response_time_ms,
            request_size=len(str(request_data.model_dump_json())),
            response_size=len(response_message)
        )
        
        context_logger.info(
            "Honeypot message processed successfully",
            extra={
                "risk_score": risk_score,
                "confidence": confidence,
                "response_length": len(response_message),
                "response_time_ms": response_time_ms
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
        
        # Record failed API usage
        await APIKeyManager.record_api_usage(
            db=db,
            api_key_record=api_key_record,
            request=request,
            status_code=400,
            response_time_ms=int((time.time() - start_time) * 1000)
        )
        
        raise HTTPException(status_code=400, detail=str(e))
        
    except HTTPException as e:
        # Re-raise HTTP exceptions
        await APIKeyManager.record_api_usage(
            db=db,
            api_key_record=api_key_record,
            request=request,
            status_code=e.status_code,
            response_time_ms=int((time.time() - start_time) * 1000)
        )
        raise
        
    except Exception as e:
        context_logger.error(f"Unexpected error processing honeypot message: {e}", exc_info=True)
        
        # Record failed API usage
        await APIKeyManager.record_api_usage(
            db=db,
            api_key_record=api_key_record,
            request=request,
            status_code=500,
            response_time_ms=int((time.time() - start_time) * 1000)
        )
        
        return HoneypotResponse(
            status="error",
            reply="I'm sorry, I'm having trouble processing your message right now. Please try again later.",
            sessionId=request_data.sessionId,
            timestamp=datetime.utcnow(),
            error="Internal processing error"
        )


def _generate_agent_placeholder_response(
    language: str, 
    persona: PersonaType, 
    risk_score: float
) -> str:
    """
    Generate placeholder response for activated agent (until full agent implementation).
    
    Args:
        language: Language code for response
        persona: Selected persona type
        risk_score: Risk score of the message
        
    Returns:
        str: Appropriate persona-based response
    """
    # Persona-specific response templates
    responses = {
        PersonaType.DIGITALLY_NAIVE: {
            'en': [
                "Oh, I'm not very good with these things. Can you help me understand?",
                "I'm not sure I understand all this technical stuff. Could you explain?",
                "This sounds important but I'm confused. What should I do?",
                "I don't know much about these things. Is this really urgent?",
                "Sorry, I'm not very tech-savvy. Can you make it simpler?"
            ],
            'hi': [
                "मुझे ये सब समझ नहीं आता। आप मदद कर सकते हैं?",
                "मैं इन technical चीजों में अच्छा नहीं हूं। समझा सकते हैं?",
                "ये important लगता है पर मैं confused हूं। क्या करना चाहिए?",
                "मुझे इन सब के बारे में ज्यादा पता नहीं। क्या ये सच में urgent है?"
            ],
            'hinglish': [
                "Mujhe ye sab samajh nahi aata. Aap help kar sakte hain?",
                "Main in technical cheezon mein achha nahi hun. Samjha sakte hain?",
                "Ye important lagta hai par main confused hun. Kya karna chahiye?",
                "Mujhe in sab ke baare mein zyada pata nahi. Kya ye sach mein urgent hai?"
            ]
        },
        PersonaType.AVERAGE_USER: {
            'en': [
                "I got your message. Let me think about this for a moment.",
                "This seems important. Can you give me more details?",
                "I want to help but I need to understand better. Can you explain?",
                "I'm interested but want to be careful. Tell me more.",
                "Let me make sure I understand this correctly. What exactly do you need?"
            ],
            'hi': [
                "आपका message मिल गया। मुझे इसके बारे में सोचने दीजिए।",
                "ये important लगता है। आप और details दे सकते हैं?",
                "मैं help करना चाहता हूं पर पहले समझना चाहता हूं।",
                "मुझे interest है पर careful रहना चाहता हूं। और बताइए।"
            ],
            'hinglish': [
                "Aapka message mil gaya. Mujhe iske baare mein sochne dijiye.",
                "Ye important lagta hai. Aap aur details de sakte hain?",
                "Main help karna chahta hun par pehle samajhna chahta hun.",
                "Mujhe interest hai par careful rehna chahta hun. Aur bataiye."
            ]
        },
        PersonaType.SKEPTICAL: {
            'en': [
                "I received your message. How do I know this is legitimate?",
                "This sounds suspicious. Can you provide some verification?",
                "I'm not comfortable with this. How can I verify your identity?",
                "I need to be sure about this. What proof can you provide?",
                "This doesn't seem right. Can you explain why I should trust this?"
            ],
            'hi': [
                "आपका message मिला। मुझे कैसे पता चले कि ये legitimate है?",
                "ये suspicious लगता है। आप कोई verification दे सकते हैं?",
                "मैं इससे comfortable नहीं हूं। आप अपनी identity कैसे verify करेंगे?",
                "मुझे इसके बारे में sure होना है। आप क्या proof दे सकते हैं?"
            ],
            'hinglish': [
                "Aapka message mila. Mujhe kaise pata chale ki ye legitimate hai?",
                "Ye suspicious lagta hai. Aap koi verification de sakte hain?",
                "Main isse comfortable nahi hun. Aap apni identity kaise verify karenge?",
                "Mujhe iske baare mein sure hona hai. Aap kya proof de sakte hain?"
            ]
        }
    }
    
    import random
    persona_responses = responses.get(persona, responses[PersonaType.AVERAGE_USER])
    language_responses = persona_responses.get(language, persona_responses['en'])
    
    return random.choice(language_responses)


def _generate_high_risk_response(language: str, risk_score: float) -> str:
    """
    Generate response for high-risk messages (potential scams).
    
    Args:
        language: Language code for response
        risk_score: Risk score of the message
        
    Returns:
        str: Appropriate response message
    """
    # For now, return non-engaging responses until agent activation is implemented
    responses = {
        'en': [
            "Thank you for your message. I'll get back to you when I can.",
            "I received your message. Let me think about it.",
            "Thanks for reaching out. I'll respond soon.",
            "I got your message. I'll need some time to consider it."
        ],
        'hi': [
            "आपके संदेश के लिए धन्यवाद। मैं जल्द ही जवाब दूंगा।",
            "मुझे आपका संदेश मिल गया है। मैं इसके बारे में सोचूंगा।",
            "संपर्क करने के लिए धन्यवाद। मैं जल्द ही जवाब दूंगा।"
        ],
        'hinglish': [
            "Thank you for your message. Main jaldi reply karunga.",
            "Aapka message mil gaya hai. Main sochke bataunga.",
            "Thanks for contacting. Main soon reply karunga."
        ]
    }
    
    import random
    response_list = responses.get(language, responses['en'])
    return random.choice(response_list)


def _generate_medium_risk_response(language: str) -> str:
    """
    Generate response for medium-risk messages.
    
    Args:
        language: Language code for response
        
    Returns:
        str: Appropriate response message
    """
    responses = {
        'en': [
            "Thank you for your message. I'll get back to you soon.",
            "I received your message. Let me check and respond.",
            "Thanks for reaching out. I'll reply when I can."
        ],
        'hi': [
            "आपके संदेश के लिए धन्यवाद। मैं जल्द ही जवाब दूंगा।",
            "मुझे आपका संदेश मिल गया है। मैं जांच कर जवाब दूंगा।"
        ],
        'hinglish': [
            "Thank you for message. Main jaldi reply karunga.",
            "Message mil gaya. Main check karke bataunga."
        ]
    }
    
    import random
    response_list = responses.get(language, responses['en'])
    return random.choice(response_list)


def _generate_low_risk_response(language: str) -> str:
    """
    Generate response for low-risk messages.
    
    Args:
        language: Language code for response
        
    Returns:
        str: Appropriate response message
    """
    responses = {
        'en': [
            "Hello! Thank you for your message.",
            "Hi there! I got your message.",
            "Thanks for reaching out!",
            "Hello! How can I help you?"
        ],
        'hi': [
            "नमस्ते! आपके संदेश के लिए धन्यवाद।",
            "हैलो! मुझे आपका संदेश मिल गया।",
            "संपर्क करने के लिए धन्यवाद!"
        ],
        'hinglish': [
            "Hello! Aapke message ke liye thank you.",
            "Hi! Aapka message mil gaya.",
            "Thanks for contacting!"
        ]
    }
    
    import random
    response_list = responses.get(language, responses['en'])
    return random.choice(response_list)