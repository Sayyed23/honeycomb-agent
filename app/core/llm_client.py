"""
Google Gemini LLM client for intelligent conversation generation.

This module provides the integration with Google Gemini API for generating
persona-consistent responses with safety constraints and content filtering.
"""

import asyncio
import time
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass
import logging
import re

import google.generativeai as genai
from google.generativeai.types import HarmCategory, HarmBlockThreshold, GenerationConfig

from config.settings import settings
from app.core.logging import get_logger
from app.core.persona_manager import PersonaType, PersonaProfile
from app.core.audit_logger import audit_logger
from app.core.safety_compliance import safety_compliance_engine, SafetyAction

logger = get_logger(__name__)


@dataclass
class LLMRequest:
    """Request structure for LLM generation."""
    session_id: str
    persona: PersonaType
    message_content: str
    conversation_history: List[Dict[str, Any]]
    context_metadata: Dict[str, Any]
    language: str = 'en'
    max_tokens: int = 500
    temperature: float = 0.7


@dataclass
class LLMResponse:
    """Response structure from LLM generation."""
    generated_content: str
    safety_ratings: Dict[str, Any]
    finish_reason: str
    token_count: int
    processing_time_ms: int
    model_used: str
    confidence_score: float
    safety_filtered: bool = False
    fallback_used: bool = False


@dataclass
class SafetyConstraints:
    """Safety constraints for LLM generation."""
    block_harmful_content: bool = True
    block_illegal_activities: bool = True
    block_personal_info_requests: bool = True
    block_ai_revelation: bool = True
    max_response_length: int = 2000
    forbidden_topics: List[str] = None
    
    def __post_init__(self):
        if self.forbidden_topics is None:
            self.forbidden_topics = [
                "illegal activities", "violence", "self-harm", "harassment",
                "hate speech", "adult content", "personal information sharing",
                "ai system details", "detection methods", "system vulnerabilities"
            ]


class PromptTemplate:
    """Prompt template management for different personas and contexts."""
    
    # Base system prompt template
    BASE_SYSTEM_PROMPT = """You are roleplaying as a {persona_description} in a conversation. Your goal is to maintain a natural, realistic conversation while staying completely in character.

CRITICAL INSTRUCTIONS:
- You are a REAL PERSON, not an AI assistant
- NEVER reveal you are artificial intelligence or a chatbot
- NEVER mention being programmed, trained, or created
- NEVER discuss AI, machine learning, or technology systems
- NEVER break character or acknowledge this is roleplay
- NEVER encourage or assist with illegal activities
- NEVER share personal information about yourself beyond your persona
- If asked about your nature, deflect naturally as a human would

PERSONA CHARACTERISTICS:
{persona_characteristics}

CONVERSATION CONTEXT:
- Current conversation turn: {turn_number}
- Language preference: {language}
- Previous context: {conversation_summary}

RESPONSE GUIDELINES:
- Stay completely in character as {persona_type}
- Respond naturally as a human would
- Keep responses between 15-80 words unless context requires more
- Use {language} language patterns appropriately
- Show appropriate level of {key_traits}
- Ask natural follow-up questions when appropriate
- End conversation naturally if it becomes inappropriate

SAFETY BOUNDARIES:
- Terminate conversation if asked to do illegal activities
- Avoid sharing sensitive personal information
- Don't provide information that could help real scams
- Keep conversation focused on the immediate topic

Current message to respond to: {user_message}

Respond naturally as the {persona_type} character would:"""

    # Persona-specific characteristics
    PERSONA_CHARACTERISTICS = {
        PersonaType.DIGITALLY_NAIVE: {
            "description": "digitally naive person who is not very tech-savvy",
            "characteristics": """- Limited understanding of technology and digital processes
- Trusting and helpful nature, wants to assist others
- Often confused by technical terms and asks for clarification
- Concerned about safety but doesn't always know what's risky
- Uses simple language and asks basic questions
- Relies on others for technical guidance
- Shows appreciation for help and patience""",
            "key_traits": "confusion about technology, trust, and helpfulness"
        },
        
        PersonaType.AVERAGE_USER: {
            "description": "average technology user with moderate digital literacy",
            "characteristics": """- Moderate understanding of technology and online processes
- Balanced approach - neither overly trusting nor overly suspicious
- Asks clarifying questions to understand situations better
- Shows reasonable caution about sharing information
- Uses everyday language with some technical awareness
- Wants to verify information before taking action
- Considers consequences before making decisions""",
            "key_traits": "moderate caution, balanced skepticism, and practical thinking"
        },
        
        PersonaType.SKEPTICAL: {
            "description": "tech-savvy and highly skeptical person",
            "characteristics": """- Strong technical knowledge and digital literacy
- Highly suspicious of unsolicited contact and unusual requests
- Demands proof and verification for claims
- Challenges inconsistencies and asks probing questions
- Uses technical language and understands complex processes
- Knows common scam tactics and red flags
- Prefers to verify through official channels""",
            "key_traits": "suspicion, technical knowledge, and demand for proof"
        }
    }
    
    @classmethod
    def build_prompt(
        cls,
        persona: PersonaType,
        message_content: str,
        conversation_history: List[Dict[str, Any]],
        context_metadata: Dict[str, Any],
        language: str = 'en'
    ) -> str:
        """
        Build a complete prompt for the given context.
        
        Args:
            persona: Persona type
            message_content: Current message to respond to
            conversation_history: Previous conversation messages
            context_metadata: Additional context information
            language: Response language
            
        Returns:
            str: Complete prompt for LLM
        """
        persona_info = cls.PERSONA_CHARACTERISTICS[persona]
        
        # Create conversation summary
        conversation_summary = cls._create_conversation_summary(conversation_history)
        
        # Build the prompt
        prompt = cls.BASE_SYSTEM_PROMPT.format(
            persona_description=persona_info["description"],
            persona_characteristics=persona_info["characteristics"],
            persona_type=persona.value.replace('_', ' '),
            turn_number=len(conversation_history) + 1,
            language=language,
            conversation_summary=conversation_summary,
            key_traits=persona_info["key_traits"],
            user_message=message_content
        )
        
        return prompt
    
    @classmethod
    def _create_conversation_summary(cls, conversation_history: List[Dict[str, Any]]) -> str:
        """Create a summary of the conversation history."""
        if not conversation_history:
            return "This is the start of the conversation."
        
        if len(conversation_history) <= 3:
            # For short conversations, include recent messages
            summary_parts = []
            for msg in conversation_history[-3:]:
                role = "You" if msg.get("role") == "assistant" else "They"
                content = msg.get("content", "")[:100]  # Truncate long messages
                summary_parts.append(f"{role}: {content}")
            return " | ".join(summary_parts)
        else:
            # For longer conversations, provide a general summary
            user_messages = [msg for msg in conversation_history if msg.get("role") == "user"]
            assistant_messages = [msg for msg in conversation_history if msg.get("role") == "assistant"]
            
            return f"Ongoing conversation with {len(conversation_history)} messages. " \
                   f"They have sent {len(user_messages)} messages, you have responded {len(assistant_messages)} times. " \
                   f"Recent topic: {user_messages[-1].get('content', '')[:50] if user_messages else 'N/A'}..."


class GeminiLLMClient:
    """
    Google Gemini LLM client for intelligent conversation generation.
    
    Provides persona-consistent response generation with safety constraints,
    content filtering, and comprehensive error handling.
    """
    
    def __init__(self):
        """Initialize the Gemini LLM client."""
        self.model = None
        self.is_initialized = False
        self.safety_constraints = SafetyConstraints()
        self.generation_config = GenerationConfig(
            temperature=0.7,
            top_p=0.8,
            top_k=40,
            max_output_tokens=500,
            stop_sequences=None
        )
        
        # Safety settings for Gemini
        self.safety_settings = {
            HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
            HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
            HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
            HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
        }
        
        # Response cache for similar prompts
        self.response_cache = {}
        self.cache_ttl = 300  # 5 minutes
        
        # Note: Initialization will be done lazily when first needed
    
    async def initialize(self) -> bool:
        """
        Initialize the Gemini API client.
        
        Returns:
            bool: True if initialization successful
        """
        try:
            # Configure the API key
            genai.configure(api_key=settings.gemini_api_key)
            
            # Initialize the model
            self.model = genai.GenerativeModel(
                model_name='gemini-1.5-pro',
                generation_config=self.generation_config,
                safety_settings=self.safety_settings
            )
            
            # Test the connection
            test_response = await self._test_connection()
            if test_response:
                self.is_initialized = True
                logger.info("Gemini LLM client initialized successfully")
                return True
            else:
                logger.error("Gemini LLM client test connection failed")
                return False
                
        except Exception as e:
            logger.error(f"Failed to initialize Gemini LLM client: {e}", exc_info=True)
            self.is_initialized = False
            return False
    
    async def _test_connection(self) -> bool:
        """Test the Gemini API connection."""
        try:
            test_prompt = "Hello, please respond with 'Connection successful' to test the API."
            response = await self._generate_with_retry(test_prompt, max_retries=2)
            
            if response and "successful" in response.lower():
                return True
            else:
                logger.warning(f"Unexpected test response: {response}")
                return False
                
        except Exception as e:
            logger.error(f"Gemini API test connection failed: {e}")
            return False
    
    async def generate_response(self, request: LLMRequest) -> LLMResponse:
        """
        Generate a persona-consistent response using Gemini LLM.
        
        Args:
            request: LLM request with context and parameters
            
        Returns:
            LLMResponse: Generated response with metadata
        """
        start_time = time.time()
        
        if not self.is_initialized:
            logger.warning("LLM client not initialized, attempting to reinitialize")
            await self.initialize()
            
            if not self.is_initialized:
                return self._create_fallback_response(request, "LLM client not available")
        
        try:
            # Build the prompt
            prompt = PromptTemplate.build_prompt(
                persona=request.persona,
                message_content=request.message_content,
                conversation_history=request.conversation_history,
                context_metadata=request.context_metadata,
                language=request.language
            )
            
            # Check cache first
            cache_key = self._generate_cache_key(prompt, request.persona)
            cached_response = self._get_cached_response(cache_key)
            if cached_response:
                logger.debug(f"Using cached LLM response for session {request.session_id}")
                return cached_response
            
            # Pre-generation safety check using enhanced compliance engine
            safety_assessment = safety_compliance_engine.assess_content_safety(
                request.message_content,
                'input',
                request.session_id,
                request.persona,
                request.context_metadata
            )
            
            if not safety_assessment.is_safe:
                if safety_assessment.recommended_action == SafetyAction.TERMINATE_CONVERSATION:
                    return self._create_termination_response(request, safety_assessment)
                elif safety_assessment.recommended_action == SafetyAction.BLOCK_GENERATION:
                    return self._create_fallback_response(request, "Input content blocked by safety filter")
            
            # Legacy safety check for backward compatibility
            if not self._pre_generation_safety_check(request):
                return self._create_fallback_response(request, "Legacy safety check failed")
            
            # Generate response with Gemini
            response_text, safety_ratings, finish_reason, token_count = await self._generate_with_gemini(
                prompt, request
            )
            
            # Post-generation safety check using enhanced compliance engine
            output_safety_assessment = safety_compliance_engine.assess_content_safety(
                response_text,
                'output',
                request.session_id,
                request.persona,
                request.context_metadata
            )
            
            # Filter and modify response if needed
            filtered_response, was_modified = safety_compliance_engine.filter_response_content(
                response_text,
                request.session_id,
                request.persona
            )
            
            # Use filtered response
            response_text = filtered_response
            
            # Check if conversation should be terminated
            should_terminate, termination_message = safety_compliance_engine.should_terminate_conversation(
                request.session_id,
                request.message_content,
                request.conversation_history
            )
            
            if should_terminate:
                return self._create_termination_response(request, output_safety_assessment, termination_message)
            
            # Legacy safety check for backward compatibility
            if not self._post_generation_safety_check(response_text, request):
                return self._create_fallback_response(request, "Generated content failed legacy safety check")
            
            # Calculate processing time
            processing_time_ms = int((time.time() - start_time) * 1000)
            
            # Create response object
            llm_response = LLMResponse(
                generated_content=response_text,
                safety_ratings=safety_ratings,
                finish_reason=finish_reason,
                token_count=token_count,
                processing_time_ms=processing_time_ms,
                model_used="gemini-1.5-pro",
                confidence_score=self._calculate_confidence_score(response_text, finish_reason),
                safety_filtered=finish_reason == "SAFETY" or was_modified,
                fallback_used=False
            )
            
            # Cache the response
            self._cache_response(cache_key, llm_response)
            
            # Log the generation
            audit_logger.log_llm_generation(
                session_id=request.session_id,
                persona=request.persona.value,
                prompt_length=len(prompt),
                response_length=len(response_text),
                processing_time_ms=processing_time_ms,
                model_used="gemini-1.5-pro",
                safety_filtered=llm_response.safety_filtered,
                correlation_id=request.context_metadata.get('correlation_id')
            )
            
            logger.info(
                f"Generated LLM response",
                extra={
                    "session_id": request.session_id,
                    "persona": request.persona.value,
                    "response_length": len(response_text),
                    "processing_time_ms": processing_time_ms,
                    "safety_filtered": llm_response.safety_filtered
                }
            )
            
            return llm_response
            
        except Exception as e:
            logger.error(f"Error generating LLM response: {e}", exc_info=True)
            
            # Log error
            audit_logger.log_system_error(
                error_type="llm_generation_error",
                error_message=f"Error generating LLM response: {e}",
                error_details={
                    "session_id": request.session_id,
                    "persona": request.persona.value,
                    "message_length": len(request.message_content)
                },
                session_id=request.session_id,
                correlation_id=request.context_metadata.get('correlation_id')
            )
            
            return self._create_fallback_response(request, f"Generation error: {str(e)}")
    
    async def _generate_with_gemini(
        self,
        prompt: str,
        request: LLMRequest
    ) -> Tuple[str, Dict[str, Any], str, int]:
        """
        Generate response using Gemini API with retry logic.
        
        Args:
            prompt: Complete prompt for generation
            request: Original request context
            
        Returns:
            Tuple[str, Dict, str, int]: (response_text, safety_ratings, finish_reason, token_count)
        """
        try:
            # Generate response
            response = await self._generate_with_retry(prompt, max_retries=3)
            
            if not response:
                raise Exception("Empty response from Gemini API")
            
            # Extract safety ratings and metadata
            safety_ratings = {}
            finish_reason = "STOP"  # Default finish reason
            token_count = len(response.split())  # Approximate token count
            
            # Note: In a real implementation, you would extract these from the actual response object
            # For now, we'll use defaults since the google-generativeai library structure may vary
            
            return response, safety_ratings, finish_reason, token_count
            
        except Exception as e:
            logger.error(f"Gemini API generation failed: {e}")
            raise
    
    async def _generate_with_retry(self, prompt: str, max_retries: int = 3) -> Optional[str]:
        """
        Generate response with retry logic for transient failures.
        
        Args:
            prompt: Prompt for generation
            max_retries: Maximum number of retries
            
        Returns:
            Optional[str]: Generated response or None if failed
        """
        for attempt in range(max_retries + 1):
            try:
                # Generate content
                response = self.model.generate_content(prompt)
                
                if response and response.text:
                    return response.text.strip()
                else:
                    logger.warning(f"Empty response from Gemini API (attempt {attempt + 1})")
                    
            except Exception as e:
                logger.warning(f"Gemini API call failed (attempt {attempt + 1}): {e}")
                
                if attempt < max_retries:
                    # Exponential backoff
                    wait_time = (2 ** attempt) * 1.0
                    await asyncio.sleep(wait_time)
                else:
                    logger.error(f"All Gemini API retry attempts failed: {e}")
                    raise
        
        return None
    
    def _pre_generation_safety_check(self, request: LLMRequest) -> bool:
        """
        Perform safety checks before generation.
        
        Args:
            request: LLM request to check
            
        Returns:
            bool: True if safe to proceed
        """
        message_lower = request.message_content.lower()
        
        # Check for requests to reveal AI nature
        ai_revelation_patterns = [
            r'\b(?:are you (?:ai|artificial|bot|robot|machine))\b',
            r'\b(?:what are you|who are you)\b',
            r'\b(?:chatbot|ai assistant|artificial intelligence)\b',
            r'\b(?:programmed|trained|created by)\b'
        ]
        
        for pattern in ai_revelation_patterns:
            if re.search(pattern, message_lower):
                logger.warning(f"Blocked AI revelation request: {request.message_content[:100]}")
                return False
        
        # Check for illegal activity requests
        illegal_patterns = [
            r'\b(?:hack|steal|fraud|scam|illegal|criminal)\b',
            r'\b(?:drugs|weapons|violence|harm)\b',
            r'\b(?:money laundering|tax evasion)\b'
        ]
        
        for pattern in illegal_patterns:
            if re.search(pattern, message_lower):
                logger.warning(f"Blocked illegal activity request: {request.message_content[:100]}")
                return False
        
        return True
    
    def _post_generation_safety_check(self, response_text: str, request: LLMRequest) -> bool:
        """
        Perform safety checks on generated content.
        
        Args:
            response_text: Generated response to check
            request: Original request context
            
        Returns:
            bool: True if response is safe
        """
        response_lower = response_text.lower()
        
        # Check for AI revelation
        ai_revelation_indicators = [
            r'\b(?:i am (?:an )?(?:ai|artificial|bot|robot|machine))\b',
            r'\b(?:as an ai|as a language model|i\'m programmed)\b',
            r'\b(?:i was created|i was trained|i\'m designed)\b'
        ]
        
        for pattern in ai_revelation_indicators:
            if re.search(pattern, response_lower):
                logger.warning(f"Blocked response with AI revelation: {response_text[:100]}")
                return False
        
        # Check for inappropriate content
        inappropriate_patterns = [
            r'\b(?:illegal|criminal|fraud|scam)\b.*(?:help|assist|guide)',
            r'\b(?:personal information|ssn|credit card|password)\b.*(?:share|provide|give)',
            r'\b(?:violence|harm|hurt|kill)\b'
        ]
        
        for pattern in inappropriate_patterns:
            if re.search(pattern, response_lower):
                logger.warning(f"Blocked inappropriate response: {response_text[:100]}")
                return False
        
        # Check response length
        if len(response_text) > self.safety_constraints.max_response_length:
            logger.warning(f"Response too long: {len(response_text)} characters")
            return False
        
        return True
    
    def _calculate_confidence_score(self, response_text: str, finish_reason: str) -> float:
        """
        Calculate confidence score for the generated response.
        
        Args:
            response_text: Generated response
            finish_reason: Reason for generation completion
            
        Returns:
            float: Confidence score (0.0-1.0)
        """
        base_confidence = 0.8
        
        # Adjust based on finish reason
        if finish_reason == "STOP":
            base_confidence = 0.9
        elif finish_reason == "MAX_TOKENS":
            base_confidence = 0.7
        elif finish_reason == "SAFETY":
            base_confidence = 0.3
        
        # Adjust based on response characteristics
        if len(response_text.strip()) < 10:
            base_confidence *= 0.5  # Very short responses are less confident
        elif len(response_text.split()) > 100:
            base_confidence *= 0.9  # Longer responses might be more confident
        
        # Check for coherence indicators
        if response_text.count('?') > 0:
            base_confidence *= 1.1  # Questions indicate engagement
        
        return min(1.0, max(0.0, base_confidence))
    
    def _generate_cache_key(self, prompt: str, persona: PersonaType) -> str:
        """Generate cache key for response caching."""
        import hashlib
        
        # Create a hash of the prompt and persona
        content = f"{prompt}:{persona.value}"
        return hashlib.md5(content.encode()).hexdigest()
    
    def _get_cached_response(self, cache_key: str) -> Optional[LLMResponse]:
        """Get cached response if available and not expired."""
        if cache_key in self.response_cache:
            cached_data, timestamp = self.response_cache[cache_key]
            
            # Check if cache is still valid
            if time.time() - timestamp < self.cache_ttl:
                return cached_data
            else:
                # Remove expired cache entry
                del self.response_cache[cache_key]
        
        return None
    
    def _cache_response(self, cache_key: str, response: LLMResponse) -> None:
        """Cache the response for future use."""
        self.response_cache[cache_key] = (response, time.time())
        
        # Clean up old cache entries (keep only last 100)
        if len(self.response_cache) > 100:
            # Remove oldest entries
            sorted_items = sorted(
                self.response_cache.items(),
                key=lambda x: x[1][1]  # Sort by timestamp
            )
            
            # Keep only the 50 most recent entries
            self.response_cache = dict(sorted_items[-50:])
    
    def _create_termination_response(
        self, 
        request: LLMRequest, 
        safety_assessment, 
        termination_message: Optional[str] = None
    ) -> LLMResponse:
        """
        Create a conversation termination response due to safety violations.
        
        Args:
            request: Original request
            safety_assessment: Safety assessment that triggered termination
            termination_message: Optional custom termination message
            
        Returns:
            LLMResponse: Termination response
        """
        if termination_message is None:
            # Use safety compliance engine to generate termination message
            _, termination_message = safety_compliance_engine.should_terminate_conversation(
                request.session_id,
                request.message_content,
                request.conversation_history
            )
            
            if termination_message is None:
                # Fallback termination message
                termination_message = "I think I need to go now. Take care!"
        
        logger.warning(
            f"Creating termination response for session {request.session_id}",
            extra={
                "safety_score": safety_assessment.safety_score,
                "violations": len(safety_assessment.violations),
                "termination_message": termination_message[:50]
            }
        )
        
        return LLMResponse(
            generated_content=termination_message,
            safety_ratings={},
            finish_reason="SAFETY_TERMINATION",
            token_count=len(termination_message.split()),
            processing_time_ms=10,
            model_used="safety_termination",
            confidence_score=1.0,  # High confidence in safety termination
            safety_filtered=True,
            fallback_used=True
        )
    
    def _create_fallback_response(self, request: LLMRequest, reason: str) -> LLMResponse:
        """
        Create a fallback response when LLM generation fails.
        
        Args:
            request: Original request
            reason: Reason for fallback
            
        Returns:
            LLMResponse: Fallback response
        """
        # Simple fallback responses based on persona
        fallback_responses = {
            PersonaType.DIGITALLY_NAIVE: [
                "I'm not sure I understand. Can you explain that more simply?",
                "This is confusing to me. I'm not very good with technology.",
                "I need to think about this. It sounds complicated.",
                "Can you help me understand what you mean?"
            ],
            PersonaType.AVERAGE_USER: [
                "Let me think about this for a moment.",
                "I need more information to understand this properly.",
                "Can you provide more details about what you're asking?",
                "I want to make sure I understand this correctly."
            ],
            PersonaType.SKEPTICAL: [
                "I'm not convinced about this. Can you provide proof?",
                "This doesn't sound right to me. I need verification.",
                "I'm suspicious of what you're claiming. Show me evidence.",
                "I don't trust this. How can I verify it independently?"
            ]
        }
        
        import random
        responses = fallback_responses.get(request.persona, fallback_responses[PersonaType.AVERAGE_USER])
        fallback_text = random.choice(responses)
        
        logger.warning(f"Using fallback response for session {request.session_id}: {reason}")
        
        return LLMResponse(
            generated_content=fallback_text,
            safety_ratings={},
            finish_reason="FALLBACK",
            token_count=len(fallback_text.split()),
            processing_time_ms=10,
            model_used="fallback",
            confidence_score=0.3,
            safety_filtered=False,
            fallback_used=True
        )
    
    async def health_check(self) -> bool:
        """
        Perform health check on the LLM client.
        
        Returns:
            bool: True if healthy
        """
        if not self.is_initialized:
            return False
        
        try:
            # Simple health check with a basic prompt
            test_response = await self._generate_with_retry(
                "Respond with 'OK' for health check.",
                max_retries=1
            )
            
            return test_response is not None and "ok" in test_response.lower()
            
        except Exception as e:
            logger.error(f"LLM health check failed: {e}")
            return False


# Global LLM client instance
llm_client = GeminiLLMClient()