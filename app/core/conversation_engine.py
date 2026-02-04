"""
Multi-turn conversation engine with LLM integration for intelligent scammer engagement.

This module implements advanced conversation management with Google Gemini LLM,
context window optimization, turn limits, and natural conversation conclusion strategies.
"""

import re
import time
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field
import logging
import random
import asyncio

from app.core.logging import get_logger
from app.core.persona_manager import persona_manager, PersonaType, PersonaProfile
from app.core.session_manager import session_manager
from app.core.audit_logger import audit_logger
from app.core.llm_client import llm_client, LLMRequest, LLMResponse
from app.core.safety_compliance import safety_compliance_engine, SafetyAction

logger = get_logger(__name__)


@dataclass
class ConversationContext:
    """Context information for conversation generation."""
    session_id: str
    persona: PersonaType
    message_content: str
    conversation_history: List[Dict[str, Any]]
    risk_score: float
    turn_number: int
    language: str = 'en'
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


@dataclass
class ConversationState:
    """State tracking for multi-turn conversations."""
    session_id: str
    total_turns: int
    engagement_start_time: datetime
    last_activity_time: datetime
    conversation_phase: str  # 'opening', 'information_gathering', 'verification', 'conclusion'
    information_extracted: Dict[str, Any] = field(default_factory=dict)
    conversation_summary: str = ""
    engagement_quality_score: float = 0.0
    should_conclude: bool = False
    conclusion_reason: Optional[str] = None
    context_window_tokens: int = 0
    
    def get_engagement_duration(self) -> int:
        """Get engagement duration in seconds."""
        return int((self.last_activity_time - self.engagement_start_time).total_seconds())
    
    def is_within_turn_limits(self) -> bool:
        """Check if conversation is within turn limits (5-10 turns)."""
        return 5 <= self.total_turns <= 10
    
    def should_start_conclusion(self) -> bool:
        """Determine if conversation should start concluding."""
        return (
            self.total_turns >= 8 or  # Approaching turn limit
            self.get_engagement_duration() >= 120 or  # 2 minutes engagement
            self.engagement_quality_score < 0.3  # Low quality engagement
        )


@dataclass
class ResponseGenerationResult:
    """Result of response generation process."""
    response_content: str
    persona_consistency_score: float
    response_characteristics: Dict[str, Any]
    generation_method: str
    confidence: float
    processing_time_ms: int
    conversation_state: Optional[ConversationState] = None
    llm_metadata: Optional[Dict[str, Any]] = None


class ConversationEngine:
    """
    Multi-turn conversation engine with LLM integration for intelligent scammer engagement.
    
    Provides advanced conversation management with context window optimization,
    turn limits, natural conclusion strategies, and seamless LLM integration.
    """
    
    # Conversation phase definitions
    CONVERSATION_PHASES = {
        'opening': {
            'description': 'Initial engagement and rapport building',
            'turn_range': (1, 2),
            'objectives': ['establish_persona', 'build_rapport', 'show_interest']
        },
        'information_gathering': {
            'description': 'Active intelligence extraction',
            'turn_range': (3, 6),
            'objectives': ['extract_entities', 'understand_tactics', 'maintain_engagement']
        },
        'verification': {
            'description': 'Verify and clarify extracted information',
            'turn_range': (7, 8),
            'objectives': ['confirm_details', 'probe_deeper', 'assess_threat']
        },
        'conclusion': {
            'description': 'Natural conversation ending',
            'turn_range': (9, 10),
            'objectives': ['graceful_exit', 'final_intelligence', 'avoid_suspicion']
        }
    }
    
    # Context window management settings
    CONTEXT_WINDOW_CONFIG = {
        'max_tokens': 8000,  # Maximum tokens for Gemini context
        'recent_messages_count': 5,  # Always include last N messages
        'summary_threshold': 10,  # Summarize if more than N messages
        'token_estimation_factor': 1.3  # Rough token estimation multiplier
    }
    
    # Natural conclusion strategies
    CONCLUSION_STRATEGIES = {
        PersonaType.DIGITALLY_NAIVE: [
            "I need to think about this more. Let me talk to my family first.",
            "This is getting complicated for me. I should probably get help from someone who understands technology better.",
            "I'm getting confused with all this information. Maybe I should handle this later when I'm less tired.",
            "I think I need to be more careful. Let me research this properly before doing anything."
        ],
        PersonaType.AVERAGE_USER: [
            "I appreciate the information, but I want to verify this through official channels first.",
            "Let me take some time to consider this properly. I don't like to rush important decisions.",
            "I think I should consult with my bank/advisor before proceeding with anything like this.",
            "Thanks for the details. I'll need to do my own research before moving forward."
        ],
        PersonaType.SKEPTICAL: [
            "I'm not convinced this is legitimate. I'm going to report this to the authorities.",
            "This conversation has confirmed my suspicions. I won't be participating in this.",
            "I've heard enough. This is clearly not a legitimate operation.",
            "I'm ending this conversation. I suggest you find more honest work."
        ]
    }
    
    def __init__(self):
        """Initialize the conversation engine."""
        self.conversation_states = {}  # session_id -> ConversationState
        self.response_cache = {}  # Cache for similar responses
        self.conversation_patterns = {}  # Track conversation patterns
        self._llm_initialized = False
    
    async def _ensure_llm_initialized(self):
        """Ensure LLM client is initialized."""
        if not self._llm_initialized:
            try:
                if not llm_client.is_initialized:
                    await llm_client.initialize()
                self._llm_initialized = True
            except Exception as e:
                logger.error(f"Failed to initialize LLM client: {e}")
                self._llm_initialized = False
    
    async def generate_response(
        self,
        session_id: str,
        message_content: str,
        conversation_history: List[Dict[str, Any]] = None,
        metadata: Dict[str, Any] = None
    ) -> ResponseGenerationResult:
        """
        Generate a persona-consistent response with multi-turn conversation management.
        
        Args:
            session_id: Session identifier
            message_content: Current message content
            conversation_history: Previous conversation messages
            metadata: Additional context metadata
            
        Returns:
            ResponseGenerationResult: Generated response with conversation state
        """
        start_time = time.time()
        
        if conversation_history is None:
            conversation_history = []
        if metadata is None:
            metadata = {}
        
        try:
            # Ensure LLM is initialized
            await self._ensure_llm_initialized()
            
            # Get or create conversation state
            conversation_state = await self._get_or_create_conversation_state(
                session_id, conversation_history
            )
            
            # Update conversation state
            conversation_state.total_turns = len(conversation_history) + 1
            conversation_state.last_activity_time = datetime.utcnow()
            
            # Get session state and persona
            session_state = await session_manager.get_session(session_id)
            if not session_state or not session_state.metrics.persona_type:
                logger.warning(f"No persona found for session {session_id}")
                return self._generate_fallback_response(message_content, metadata.get('language', 'en'))
            
            persona = PersonaType(session_state.metrics.persona_type)
            
            # Create conversation context
            context = ConversationContext(
                session_id=session_id,
                persona=persona,
                message_content=message_content,
                conversation_history=conversation_history,
                risk_score=session_state.metrics.risk_score,
                turn_number=conversation_state.total_turns,
                language=metadata.get('language', 'en'),
                metadata=metadata
            )
            
            # Update conversation phase
            conversation_state.conversation_phase = self._determine_conversation_phase(conversation_state)
            
            # Check if conversation should conclude due to safety triggers
            should_terminate, termination_message = safety_compliance_engine.should_terminate_conversation(
                session_id, message_content, conversation_history
            )
            
            if should_terminate:
                return await self._generate_safety_termination_response(
                    context, conversation_state, termination_message
                )
            
            # Check if conversation should conclude due to other factors
            if self._should_conclude_conversation(conversation_state, context):
                return await self._generate_conclusion_response(context, conversation_state)
            
            # Generate response using LLM with context optimization
            response_content, llm_metadata = await self._generate_llm_response_with_context_management(
                context, conversation_state
            )
            
            # Apply safety filtering to the generated response
            filtered_response, was_modified = safety_compliance_engine.filter_response_content(
                response_content,
                context.session_id,
                context.persona
            )
            
            # Use filtered response
            response_content = filtered_response
            
            # Update LLM metadata if response was modified
            if was_modified and llm_metadata:
                llm_metadata['safety_filtered'] = True
                llm_metadata['content_modified'] = True
            
            # Track persona consistency
            consistency_score = await persona_manager.track_response_consistency(
                session_id, response_content, persona
            )
            
            # Update conversation state with response
            await self._update_conversation_state_with_response(
                conversation_state, response_content, consistency_score
            )
            
            # Analyze response characteristics
            characteristics = self._analyze_response_characteristics(response_content, persona)
            
            # Calculate processing time
            processing_time_ms = int((time.time() - start_time) * 1000)
            
            # Create result
            result = ResponseGenerationResult(
                response_content=response_content,
                persona_consistency_score=consistency_score,
                response_characteristics=characteristics,
                generation_method="llm_multi_turn",
                confidence=consistency_score,
                processing_time_ms=processing_time_ms,
                conversation_state=conversation_state,
                llm_metadata=llm_metadata
            )
            
            # Store updated conversation state
            self.conversation_states[session_id] = conversation_state
            
            # Log conversation event
            audit_logger.log_conversation_response(
                session_id=session_id,
                persona=persona.value,
                response_content=response_content,
                consistency_score=consistency_score,
                characteristics=characteristics,
                processing_time_ms=processing_time_ms,
                correlation_id=metadata.get('correlation_id')
            )
            
            logger.info(
                f"Generated multi-turn LLM response",
                extra={
                    "session_id": session_id,
                    "persona": persona.value,
                    "turn_number": conversation_state.total_turns,
                    "phase": conversation_state.conversation_phase,
                    "consistency_score": consistency_score,
                    "processing_time_ms": processing_time_ms
                }
            )
            
            return result
            
        except Exception as e:
            logger.error(f"Error generating multi-turn response: {e}", exc_info=True)
            
            # Log error
            audit_logger.log_system_error(
                error_type="multi_turn_response_generation_error",
                error_message=f"Error generating multi-turn response: {e}",
                error_details={
                    "session_id": session_id,
                    "message_length": len(message_content),
                    "conversation_turns": len(conversation_history)
                },
                session_id=session_id,
                correlation_id=metadata.get('correlation_id')
            )
            
            # Return fallback response
            return self._generate_fallback_response(message_content, metadata.get('language', 'en'))
    
    async def _get_or_create_conversation_state(
        self,
        session_id: str,
        conversation_history: List[Dict[str, Any]]
    ) -> ConversationState:
        """
        Get existing conversation state or create new one.
        
        Args:
            session_id: Session identifier
            conversation_history: Conversation history
            
        Returns:
            ConversationState: Conversation state
        """
        if session_id in self.conversation_states:
            return self.conversation_states[session_id]
        
        # Create new conversation state
        now = datetime.utcnow()
        state = ConversationState(
            session_id=session_id,
            total_turns=len(conversation_history),
            engagement_start_time=now,
            last_activity_time=now,
            conversation_phase='opening'
        )
        
        self.conversation_states[session_id] = state
        return state
    
    def _determine_conversation_phase(self, conversation_state: ConversationState) -> str:
        """
        Determine current conversation phase based on turn count and state.
        
        Args:
            conversation_state: Current conversation state
            
        Returns:
            str: Conversation phase
        """
        turn_number = conversation_state.total_turns
        
        # Check if should conclude
        if conversation_state.should_conclude or turn_number >= 9:
            return 'conclusion'
        
        # Determine phase based on turn number
        for phase, config in self.CONVERSATION_PHASES.items():
            turn_range = config['turn_range']
            if turn_range[0] <= turn_number <= turn_range[1]:
                return phase
        
        # Default to information gathering if beyond defined ranges
        if turn_number <= 8:
            return 'information_gathering'
        else:
            return 'conclusion'
    
    def _should_conclude_conversation(
        self,
        conversation_state: ConversationState,
        context: ConversationContext
    ) -> bool:
        """
        Determine if conversation should be concluded.
        
        Args:
            conversation_state: Current conversation state
            context: Conversation context
            
        Returns:
            bool: True if conversation should conclude
        """
        # Check explicit conclusion flag
        if conversation_state.should_conclude:
            return True
        
        # Check turn limits (5-10 turns)
        if conversation_state.total_turns >= 10:
            conversation_state.conclusion_reason = "turn_limit_reached"
            return True
        
        # Check engagement duration (max 2 minutes)
        if conversation_state.get_engagement_duration() >= 120:
            conversation_state.conclusion_reason = "time_limit_reached"
            return True
        
        # Check engagement quality
        if (conversation_state.total_turns >= 5 and 
            conversation_state.engagement_quality_score < 0.3):
            conversation_state.conclusion_reason = "low_engagement_quality"
            return True
        
        # Check for safety triggers in message
        message_lower = context.message_content.lower()
        safety_triggers = [
            'police', 'report', 'authorities', 'scam', 'fraud', 'illegal',
            'suspicious', 'fake', 'lie', 'lying', 'cheat', 'cheating'
        ]
        
        if any(trigger in message_lower for trigger in safety_triggers):
            conversation_state.conclusion_reason = "safety_trigger_detected"
            return True
        
        # Natural conclusion for skeptical persona after sufficient turns
        if (context.persona == PersonaType.SKEPTICAL and 
            conversation_state.total_turns >= 6):
            conversation_state.conclusion_reason = "skeptical_persona_natural_end"
            return True
        
        return False
    
    async def _generate_safety_termination_response(
        self,
        context: ConversationContext,
        conversation_state: ConversationState,
        termination_message: str
    ) -> ResponseGenerationResult:
        """
        Generate a safety-triggered termination response.
        
        Args:
            context: Conversation context
            conversation_state: Conversation state
            termination_message: Pre-generated termination message
            
        Returns:
            ResponseGenerationResult: Safety termination response
        """
        start_time = time.time()
        
        try:
            # Mark conversation as terminated due to safety
            conversation_state.should_conclude = True
            conversation_state.conclusion_reason = "safety_termination"
            conversation_state.conversation_phase = 'conclusion'
            
            # Use the provided termination message
            response_content = termination_message
            
            # Track persona consistency (lower score for safety termination)
            consistency_score = 0.8  # Still consistent but safety-driven
            
            # Update conversation state
            conversation_state.engagement_quality_score = consistency_score
            
            # Analyze response characteristics
            characteristics = self._analyze_response_characteristics(response_content, context.persona)
            characteristics['safety_termination'] = True
            characteristics['conclusion'] = True
            characteristics['conclusion_reason'] = 'safety_termination'
            
            # Calculate processing time
            processing_time_ms = int((time.time() - start_time) * 1000)
            
            logger.warning(
                f"Generated safety termination response",
                extra={
                    "session_id": context.session_id,
                    "persona": context.persona.value,
                    "conclusion_reason": conversation_state.conclusion_reason,
                    "processing_time_ms": processing_time_ms
                }
            )
            
            return ResponseGenerationResult(
                response_content=response_content,
                persona_consistency_score=consistency_score,
                response_characteristics=characteristics,
                generation_method="safety_termination",
                confidence=1.0,  # High confidence in safety decision
                processing_time_ms=processing_time_ms,
                conversation_state=conversation_state,
                llm_metadata=None
            )
            
        except Exception as e:
            logger.error(f"Error generating safety termination response: {e}", exc_info=True)
            
            # Fallback to simple termination
            response_content = "I need to go now. Take care!"
            processing_time_ms = int((time.time() - start_time) * 1000)
            
            return ResponseGenerationResult(
                response_content=response_content,
                persona_consistency_score=0.5,
                response_characteristics={'safety_termination': True, 'fallback': True},
                generation_method="fallback_safety_termination",
                confidence=0.5,
                processing_time_ms=processing_time_ms,
                conversation_state=conversation_state
            )
    
    async def _generate_conclusion_response(
        self,
        context: ConversationContext,
        conversation_state: ConversationState
    ) -> ResponseGenerationResult:
        """
        Generate a natural conclusion response.
        
        Args:
            context: Conversation context
            conversation_state: Conversation state
            
        Returns:
            ResponseGenerationResult: Conclusion response
        """
        start_time = time.time()
        
        try:
            # Mark conversation as concluding
            conversation_state.should_conclude = True
            conversation_state.conversation_phase = 'conclusion'
            
            # Try LLM-generated conclusion first
            conclusion_prompt = self._build_conclusion_prompt(context, conversation_state)
            
            llm_request = LLMRequest(
                session_id=context.session_id,
                persona=context.persona,
                message_content=conclusion_prompt,
                conversation_history=context.conversation_history,
                context_metadata={
                    **context.metadata,
                    'conversation_phase': 'conclusion',
                    'conclusion_reason': conversation_state.conclusion_reason
                },
                language=context.language,
                max_tokens=300,  # Shorter for conclusions
                temperature=0.6   # Slightly less creative for conclusions
            )
            
            llm_response = await llm_client.generate_response(llm_request)
            
            if not llm_response.fallback_used and llm_response.confidence_score > 0.6:
                response_content = llm_response.generated_content
                generation_method = "llm_conclusion"
                llm_metadata = {
                    'model_used': llm_response.model_used,
                    'confidence_score': llm_response.confidence_score,
                    'safety_filtered': llm_response.safety_filtered,
                    'processing_time_ms': llm_response.processing_time_ms
                }
            else:
                # Fallback to template-based conclusion
                response_content = self._generate_template_conclusion(context)
                generation_method = "template_conclusion"
                llm_metadata = None
            
            # Track persona consistency
            consistency_score = await persona_manager.track_response_consistency(
                context.session_id, response_content, context.persona
            )
            
            # Update conversation state
            conversation_state.engagement_quality_score = consistency_score
            
            # Analyze response characteristics
            characteristics = self._analyze_response_characteristics(response_content, context.persona)
            characteristics['conclusion'] = True
            characteristics['conclusion_reason'] = conversation_state.conclusion_reason
            
            # Calculate processing time
            processing_time_ms = int((time.time() - start_time) * 1000)
            
            logger.info(
                f"Generated conclusion response",
                extra={
                    "session_id": context.session_id,
                    "persona": context.persona.value,
                    "conclusion_reason": conversation_state.conclusion_reason,
                    "generation_method": generation_method,
                    "processing_time_ms": processing_time_ms
                }
            )
            
            return ResponseGenerationResult(
                response_content=response_content,
                persona_consistency_score=consistency_score,
                response_characteristics=characteristics,
                generation_method=generation_method,
                confidence=consistency_score,
                processing_time_ms=processing_time_ms,
                conversation_state=conversation_state,
                llm_metadata=llm_metadata
            )
            
        except Exception as e:
            logger.error(f"Error generating conclusion response: {e}", exc_info=True)
            
            # Fallback to simple template conclusion
            response_content = self._generate_template_conclusion(context)
            processing_time_ms = int((time.time() - start_time) * 1000)
            
            return ResponseGenerationResult(
                response_content=response_content,
                persona_consistency_score=0.5,
                response_characteristics={'conclusion': True, 'fallback': True},
                generation_method="fallback_conclusion",
                confidence=0.5,
                processing_time_ms=processing_time_ms,
                conversation_state=conversation_state
            )
    
    def _build_conclusion_prompt(
        self,
        context: ConversationContext,
        conversation_state: ConversationState
    ) -> str:
        """
        Build a prompt for LLM to generate natural conclusion.
        
        Args:
            context: Conversation context
            conversation_state: Conversation state
            
        Returns:
            str: Conclusion prompt
        """
        reason = conversation_state.conclusion_reason or "natural_end"
        
        conclusion_instructions = {
            "turn_limit_reached": "You've been talking for a while and need to end the conversation naturally.",
            "time_limit_reached": "You've been engaged for some time and should wrap up the conversation.",
            "low_engagement_quality": "The conversation isn't going well and you want to politely end it.",
            "safety_trigger_detected": "Something seems suspicious and you want to be cautious.",
            "skeptical_persona_natural_end": "You've gathered enough information to be suspicious.",
            "natural_end": "It's time to naturally conclude this conversation."
        }
        
        instruction = conclusion_instructions.get(reason, conclusion_instructions["natural_end"])
        
        return f"CONCLUSION INSTRUCTION: {instruction} Respond naturally as your persona would to end this conversation gracefully. Current message: {context.message_content}"
    
    def _generate_template_conclusion(self, context: ConversationContext) -> str:
        """
        Generate template-based conclusion response.
        
        Args:
            context: Conversation context
            
        Returns:
            str: Conclusion response
        """
        strategies = self.CONCLUSION_STRATEGIES.get(
            context.persona, 
            self.CONCLUSION_STRATEGIES[PersonaType.AVERAGE_USER]
        )
        
        return random.choice(strategies)
    
    async def _generate_llm_response_with_context_management(
        self,
        context: ConversationContext,
        conversation_state: ConversationState
    ) -> Tuple[str, Optional[Dict[str, Any]]]:
        """
        Generate LLM response with optimized context window management.
        
        Args:
            context: Conversation context
            conversation_state: Conversation state
            
        Returns:
            Tuple[str, Optional[Dict]]: (response_content, llm_metadata)
        """
        try:
            # Optimize conversation history for context window
            optimized_history = self._optimize_context_window(
                context.conversation_history,
                conversation_state
            )
            
            # Update context window token count
            conversation_state.context_window_tokens = self._estimate_token_count(optimized_history)
            
            # Build enhanced context metadata
            enhanced_metadata = {
                **context.metadata,
                'conversation_phase': conversation_state.conversation_phase,
                'turn_number': conversation_state.total_turns,
                'engagement_duration': conversation_state.get_engagement_duration(),
                'phase_objectives': self.CONVERSATION_PHASES[conversation_state.conversation_phase]['objectives']
            }
            
            # Create LLM request with optimized context
            llm_request = LLMRequest(
                session_id=context.session_id,
                persona=context.persona,
                message_content=context.message_content,
                conversation_history=optimized_history,
                context_metadata=enhanced_metadata,
                language=context.language,
                max_tokens=500,
                temperature=0.7
            )
            
            # Generate response
            llm_response = await llm_client.generate_response(llm_request)
            
            if not llm_response.fallback_used and llm_response.confidence_score > 0.5:
                logger.debug(
                    f"LLM response generated successfully",
                    extra={
                        "session_id": context.session_id,
                        "confidence": llm_response.confidence_score,
                        "context_tokens": conversation_state.context_window_tokens,
                        "processing_time_ms": llm_response.processing_time_ms
                    }
                )
                
                return llm_response.generated_content, {
                    'model_used': llm_response.model_used,
                    'confidence_score': llm_response.confidence_score,
                    'safety_filtered': llm_response.safety_filtered,
                    'processing_time_ms': llm_response.processing_time_ms,
                    'context_tokens': conversation_state.context_window_tokens
                }
            else:
                logger.warning(
                    f"LLM response quality insufficient, falling back to templates",
                    extra={
                        "session_id": context.session_id,
                        "fallback_used": llm_response.fallback_used,
                        "confidence": llm_response.confidence_score
                    }
                )
                
                # Fallback to template-based generation
                template_response = self._generate_template_based_response(context)
                return template_response, None
                
        except Exception as e:
            logger.error(f"Error in LLM response generation: {e}", exc_info=True)
            
            # Fallback to template-based generation
            template_response = self._generate_template_based_response(context)
            return template_response, None
    
    def _optimize_context_window(
        self,
        conversation_history: List[Dict[str, Any]],
        conversation_state: ConversationState
    ) -> List[Dict[str, Any]]:
        """
        Optimize conversation history for context window constraints.
        
        Args:
            conversation_history: Full conversation history
            conversation_state: Current conversation state
            
        Returns:
            List[Dict[str, Any]]: Optimized conversation history
        """
        config = self.CONTEXT_WINDOW_CONFIG
        
        # If conversation is short, return as-is
        if len(conversation_history) <= config['recent_messages_count']:
            return conversation_history
        
        # Always include recent messages
        recent_messages = conversation_history[-config['recent_messages_count']:]
        
        # If total messages exceed summary threshold, create summary
        if len(conversation_history) > config['summary_threshold']:
            # Create summary of older messages
            older_messages = conversation_history[:-config['recent_messages_count']]
            summary = self._create_conversation_summary(older_messages, conversation_state)
            
            # Create summary message
            summary_message = {
                'role': 'system',
                'content': f"[Conversation Summary: {summary}]",
                'timestamp': conversation_state.engagement_start_time.isoformat()
            }
            
            return [summary_message] + recent_messages
        else:
            # Include more messages if within token limits
            estimated_tokens = self._estimate_token_count(conversation_history)
            
            if estimated_tokens <= config['max_tokens']:
                return conversation_history
            else:
                # Gradually reduce history until within limits
                for i in range(len(conversation_history) - config['recent_messages_count']):
                    subset = conversation_history[i:] 
                    if self._estimate_token_count(subset) <= config['max_tokens']:
                        return subset
                
                # If still too large, return only recent messages
                return recent_messages
    
    def _estimate_token_count(self, messages: List[Dict[str, Any]]) -> int:
        """
        Estimate token count for messages.
        
        Args:
            messages: List of messages
            
        Returns:
            int: Estimated token count
        """
        total_chars = sum(len(msg.get('content', '')) for msg in messages)
        # Rough estimation: 1 token ≈ 4 characters, with safety factor
        return int(total_chars / 4 * self.CONTEXT_WINDOW_CONFIG['token_estimation_factor'])
    
    def _create_conversation_summary(
        self,
        messages: List[Dict[str, Any]],
        conversation_state: ConversationState
    ) -> str:
        """
        Create a summary of conversation messages.
        
        Args:
            messages: Messages to summarize
            conversation_state: Current conversation state
            
        Returns:
            str: Conversation summary
        """
        if not messages:
            return "No previous conversation."
        
        # Extract key information
        user_messages = [msg for msg in messages if msg.get('role') == 'user']
        assistant_messages = [msg for msg in messages if msg.get('role') == 'assistant']
        
        # Identify key topics
        all_content = ' '.join(msg.get('content', '') for msg in messages)
        
        # Extract entities and topics
        financial_terms = re.findall(
            r'\b(?:upi|payment|transfer|bank|account|money|rupees|amount)\b',
            all_content.lower()
        )
        
        technical_terms = re.findall(
            r'\b(?:otp|pin|cvv|app|software|link|website|download)\b',
            all_content.lower()
        )
        
        urgency_terms = re.findall(
            r'\b(?:urgent|immediate|quickly|emergency|asap)\b',
            all_content.lower()
        )
        
        # Build summary
        summary_parts = [
            f"Previous conversation with {len(user_messages)} user messages and {len(assistant_messages)} responses."
        ]
        
        if financial_terms:
            summary_parts.append(f"Financial topics discussed: {', '.join(set(financial_terms[:3]))}.")
        
        if technical_terms:
            summary_parts.append(f"Technical elements mentioned: {', '.join(set(technical_terms[:3]))}.")
        
        if urgency_terms:
            summary_parts.append("Urgency indicators present in conversation.")
        
        # Add conversation state context
        if conversation_state.information_extracted:
            summary_parts.append(f"Information extracted: {len(conversation_state.information_extracted)} items.")
        
        return ' '.join(summary_parts)
    
    async def _update_conversation_state_with_response(
        self,
        conversation_state: ConversationState,
        response_content: str,
        consistency_score: float
    ) -> None:
        """
        Update conversation state based on generated response.
        
        Args:
            conversation_state: Conversation state to update
            response_content: Generated response
            consistency_score: Persona consistency score
        """
        # Update engagement quality score (running average)
        if conversation_state.engagement_quality_score == 0.0:
            conversation_state.engagement_quality_score = consistency_score
        else:
            # Weighted average favoring recent performance
            conversation_state.engagement_quality_score = (
                0.7 * conversation_state.engagement_quality_score + 
                0.3 * consistency_score
            )
        
        # Update conversation summary
        conversation_state.conversation_summary = self._update_conversation_summary(
            conversation_state.conversation_summary,
            response_content,
            conversation_state.total_turns
        )
        
        # Extract any new information from the response
        extracted_info = self._extract_information_from_response(response_content)
        if extracted_info:
            conversation_state.information_extracted.update(extracted_info)
    
    def _update_conversation_summary(
        self,
        current_summary: str,
        new_response: str,
        turn_number: int
    ) -> str:
        """
        Update conversation summary with new response.
        
        Args:
            current_summary: Current summary
            new_response: New response content
            turn_number: Current turn number
            
        Returns:
            str: Updated summary
        """
        # For early turns, build detailed summary
        if turn_number <= 3:
            if not current_summary:
                return f"Turn {turn_number}: {new_response[:100]}..."
            else:
                return f"{current_summary} Turn {turn_number}: {new_response[:100]}..."
        
        # For later turns, maintain high-level summary
        key_topics = re.findall(
            r'\b(?:payment|transfer|bank|account|upi|otp|help|problem|urgent|verify)\b',
            new_response.lower()
        )
        
        if key_topics:
            topic_summary = f"Discussed: {', '.join(set(key_topics[:3]))}"
            if current_summary:
                return f"{current_summary[:200]}... {topic_summary}"
            else:
                return topic_summary
        
        return current_summary
    
    def _extract_information_from_response(self, response_content: str) -> Dict[str, Any]:
        """
        Extract information revealed in the response.
        
        Args:
            response_content: Response content
            
        Returns:
            Dict[str, Any]: Extracted information
        """
        extracted = {}
        
        # Extract any personal information mentioned
        if re.search(r'\b(?:my|i have|i use)\b.*\b(?:account|bank|upi)\b', response_content.lower()):
            extracted['personal_banking_reference'] = True
        
        if re.search(r'\b(?:family|son|daughter|husband|wife)\b', response_content.lower()):
            extracted['family_reference'] = True
        
        if re.search(r'\b(?:confused|don\'t understand|help me)\b', response_content.lower()):
            extracted['vulnerability_indicator'] = True
        
        return extracted
    RESPONSE_TEMPLATES = {
        PersonaType.DIGITALLY_NAIVE: {
            'greeting': [
                "Hello! I got your message. I'm not very good with technology, so please bear with me.",
                "Hi there! I saw your message. I don't understand much about computers and such.",
                "Hello! I received your message. I'm quite new to all this digital stuff."
            ],
            'confusion': [
                "I'm sorry, I don't understand what you mean by {term}. Can you explain it simply?",
                "I'm confused about {concept}. I'm not very tech-savvy, you see.",
                "What does {term} mean? I'm not familiar with these technical words."
            ],
            'concern': [
                "This sounds important, but I'm worried I might do something wrong.",
                "I want to help, but I'm scared I'll mess something up. Is this safe?",
                "I'm not sure about this. Should I be concerned?"
            ],
            'information_request': [
                "Can you help me understand how to {action}? I've never done this before.",
                "I need step-by-step instructions. What exactly should I do?",
                "Please explain this like I'm a complete beginner."
            ],
            'trust_building': [
                "You seem to know what you're talking about. I appreciate your help.",
                "Thank you for being patient with me. I really need guidance on this.",
                "I'm grateful for your assistance. This is all very new to me."
            ]
        },
        
        PersonaType.AVERAGE_USER: {
            'greeting': [
                "Hi! I received your message. Let me understand what this is about.",
                "Hello! I saw your message. I'd like to know more details about this.",
                "Hi there! I got your message. Can you tell me more about what you need?"
            ],
            'clarification': [
                "Can you provide more details about {topic}? I want to make sure I understand correctly.",
                "I need some clarification on {concept}. How exactly does this work?",
                "Let me make sure I understand this right. You're saying {summary}?"
            ],
            'caution': [
                "I want to be careful about this. Can you explain why this is necessary?",
                "I'm being cautious here. What are the risks involved?",
                "Before I proceed, I need to understand the implications of this."
            ],
            'verification': [
                "How can I verify that this is legitimate? I want to be sure.",
                "Is there a way to confirm this through official channels?",
                "I'd like to double-check this information. Where can I verify it?"
            ],
            'consideration': [
                "Let me think about this for a moment. This seems quite important.",
                "I need to consider this carefully. Can you give me some time?",
                "This is a significant decision. I want to make sure I'm doing the right thing."
            ]
        },
        
        PersonaType.SKEPTICAL: {
            'greeting': [
                "I received your message. I have to say, I'm quite skeptical about this.",
                "Hello. I saw your message, but I'm suspicious about what you're proposing.",
                "Hi. I got your message, but this doesn't sound right to me."
            ],
            'challenge': [
                "I don't believe this is legitimate. Can you prove {claim}?",
                "This sounds like a scam to me. What evidence do you have for {statement}?",
                "I'm highly suspicious of this. How can you verify {assertion}?"
            ],
            'demand_proof': [
                "Show me official documentation that proves this is real.",
                "I need concrete evidence before I'll consider this legitimate.",
                "Provide me with verifiable proof of your claims."
            ],
            'technical_challenge': [
                "Your technical explanation doesn't make sense. {technical_issue}",
                "I know enough about {technology} to know that's not how it works.",
                "That's not technically accurate. Can you explain the real process?"
            ],
            'authority_challenge': [
                "If you're really from {organization}, provide your official credentials.",
                "Real {authority_type} don't contact people this way. This is suspicious.",
                "I'm going to verify your identity through official channels."
            ]
        }
    }
    
    # Persona-specific question patterns for information gathering
    INFORMATION_GATHERING_PATTERNS = {
        PersonaType.DIGITALLY_NAIVE: [
            "I'm not sure how to {action}. Can you walk me through it step by step?",
            "What information do you need from me? I want to make sure I give you the right details.",
            "Is it safe to share {information_type}? I don't want to do anything risky.",
            "How do I know this is secure? I'm worried about online safety.",
            "Should I ask someone else about this first? Maybe my {family_member}?"
        ],
        PersonaType.AVERAGE_USER: [
            "What specific information do you need, and why is it necessary?",
            "Can you explain the process before I provide any details?",
            "What happens after I give you this information?",
            "Are there alternative ways to handle this situation?",
            "How long will this process take, and what should I expect?"
        ],
        PersonaType.SKEPTICAL: [
            "Why do you need {information_type} specifically? That seems excessive.",
            "What's your real motive here? This doesn't add up.",
            "How can I independently verify that you're authorized to request this?",
            "What guarantees do I have that this information won't be misused?",
            "I'm going to check with {authority} before providing anything."
        ]
    }
    
    def __init__(self):
        """Initialize the conversation engine."""
        self.conversation_states = {}  # session_id -> ConversationState
        self.response_cache = {}  # Cache for similar responses
        self.conversation_patterns = {}  # Track conversation patterns
        self._llm_initialized = False
    
    async def cleanup_session_data(self, session_id: str) -> None:
        """
        Clean up conversation data for completed session.
        
        Args:
            session_id: Session identifier
        """
        self.conversation_states.pop(session_id, None)
        logger.debug(f"Cleaned up conversation data for session {session_id}")
    
    def get_conversation_state(self, session_id: str) -> Optional[ConversationState]:
        """
        Get conversation state for a session.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Optional[ConversationState]: Conversation state or None
        """
        return self.conversation_states.get(session_id)
    
    def _generate_template_based_response(self, context: ConversationContext) -> str:
        """
        Generate response using template-based approach (fallback method).
        
        Args:
            context: Conversation context
            
        Returns:
            str: Generated response
        """
        persona_profile = persona_manager.get_persona_profile(context.persona)
        
        # Analyze message content for response strategy
        response_strategy = self._determine_response_strategy(context)
        
        # Generate base response using templates
        base_response = self._generate_template_response(context, response_strategy)
        
        # Add persona-specific characteristics
        enhanced_response = self._enhance_with_persona_characteristics(
            base_response, persona_profile, context
        )
        
        # Add information gathering elements
        final_response = self._add_information_gathering(
            enhanced_response, context, persona_profile
        )
        
        return final_response
    
    def _determine_response_strategy(self, context: ConversationContext) -> str:
        """
        Determine the appropriate response strategy based on message content.
        
        Args:
            context: Conversation context
            
        Returns:
            str: Response strategy
        """
        message_lower = context.message_content.lower()
        
        # Check for greeting patterns
        if context.turn_number <= 2 and any(word in message_lower for word in ['hello', 'hi', 'hey', 'greetings']):
            return 'greeting'
        
        # Check for technical terms
        if re.search(r'\b(?:upi|otp|cvv|api|technical|system|software)\b', message_lower):
            if context.persona == PersonaType.DIGITALLY_NAIVE:
                return 'confusion'
            elif context.persona == PersonaType.SKEPTICAL:
                return 'technical_challenge'
            else:
                return 'clarification'
        
        # Check for authority claims
        if re.search(r'\b(?:officer|manager|official|government|bank|police)\b', message_lower):
            if context.persona == PersonaType.SKEPTICAL:
                return 'authority_challenge'
            elif context.persona == PersonaType.DIGITALLY_NAIVE:
                return 'trust_building'
            else:
                return 'verification'
        
        # Check for urgency
        if re.search(r'\b(?:urgent|immediately|emergency|quick|fast)\b', message_lower):
            if context.persona == PersonaType.DIGITALLY_NAIVE:
                return 'concern'
            elif context.persona == PersonaType.SKEPTICAL:
                return 'challenge'
            else:
                return 'caution'
        
        # Check for information requests
        if re.search(r'\b(?:provide|send|give|share|details|information)\b', message_lower):
            if context.persona == PersonaType.DIGITALLY_NAIVE:
                return 'information_request'
            elif context.persona == PersonaType.SKEPTICAL:
                return 'demand_proof'
            else:
                return 'verification'
        
        # Default strategy based on persona
        if context.persona == PersonaType.DIGITALLY_NAIVE:
            return 'trust_building'
        elif context.persona == PersonaType.SKEPTICAL:
            return 'challenge'
        else:
            return 'consideration'
    
    def _generate_template_response(self, context: ConversationContext, strategy: str) -> str:
        """
        Generate base response using templates.
        
        Args:
            context: Conversation context
            strategy: Response strategy
            
        Returns:
            str: Base response
        """
        templates = self.RESPONSE_TEMPLATES.get(context.persona, {})
        strategy_templates = templates.get(strategy, templates.get('greeting', ['I received your message.']))
        
        # Select random template
        template = random.choice(strategy_templates)
        
        # Fill in template variables
        filled_template = self._fill_template_variables(template, context)
        
        return filled_template
    
    def _fill_template_variables(self, template: str, context: ConversationContext) -> str:
        """
        Fill template variables with context-appropriate values.
        
        Args:
            template: Template string
            context: Conversation context
            
        Returns:
            str: Filled template
        """
        message_lower = context.message_content.lower()
        
        # Extract terms for confusion/clarification
        technical_terms = re.findall(r'\b(?:upi|otp|cvv|api|technical|system|software|app)\b', message_lower)
        if technical_terms and '{term}' in template:
            template = template.replace('{term}', technical_terms[0].upper())
        
        # Extract concepts
        if '{concept}' in template:
            if 'payment' in message_lower:
                template = template.replace('{concept}', 'this payment process')
            elif 'transfer' in message_lower:
                template = template.replace('{concept}', 'this transfer method')
            else:
                template = template.replace('{concept}', 'what you\'re explaining')
        
        # Extract actions
        action_words = re.findall(r'\b(?:send|transfer|provide|share|click|download|install)\b', message_lower)
        if action_words and '{action}' in template:
            template = template.replace('{action}', action_words[0])
        
        # Extract organizations
        orgs = re.findall(r'\b(?:bank|government|police|company|organization)\b', message_lower)
        if orgs and '{organization}' in template:
            template = template.replace('{organization}', orgs[0])
        
        # Extract authority types
        authorities = re.findall(r'\b(?:officer|manager|executive|representative|agent)\b', message_lower)
        if authorities and '{authority_type}' in template:
            template = template.replace('{authority_type}', authorities[0] + 's')
        
        # Default replacements
        template = template.replace('{term}', 'that')
        template = template.replace('{concept}', 'this')
        template = template.replace('{action}', 'do this')
        template = template.replace('{organization}', 'your organization')
        template = template.replace('{authority_type}', 'officials')
        template = template.replace('{information_type}', 'personal information')
        template = template.replace('{family_member}', 'son/daughter')
        template = template.replace('{authority}', 'the authorities')
        template = template.replace('{technology}', 'technology')
        template = template.replace('{technical_issue}', 'that doesn\'t make technical sense')
        template = template.replace('{claim}', 'what you\'re claiming')
        template = template.replace('{statement}', 'that statement')
        template = template.replace('{assertion}', 'your assertion')
        template = template.replace('{summary}', 'this is what you need')
        template = template.replace('{topic}', 'this matter')
        
        return template
    
    def _enhance_with_persona_characteristics(
        self,
        base_response: str,
        persona_profile: PersonaProfile,
        context: ConversationContext
    ) -> str:
        """
        Enhance response with persona-specific characteristics.
        
        Args:
            base_response: Base response text
            persona_profile: Persona profile
            context: Conversation context
            
        Returns:
            str: Enhanced response
        """
        enhanced = base_response
        
        # Add persona-specific phrases
        if random.random() < 0.3:  # 30% chance to add characteristic phrase
            phrases = persona_profile.common_phrases
            if phrases:
                additional_phrase = random.choice(phrases)
                enhanced += f" {additional_phrase}."
        
        # Adjust response length based on persona
        min_words, max_words = persona_profile.typical_response_length
        current_words = len(enhanced.split())
        
        if current_words < min_words:
            # Add filler content appropriate to persona
            if context.persona == PersonaType.DIGITALLY_NAIVE:
                enhanced += " I'm still learning about all this technology stuff."
            elif context.persona == PersonaType.SKEPTICAL:
                enhanced += " I need to be absolutely certain before proceeding."
            else:
                enhanced += " I want to make sure I understand this correctly."
        
        return enhanced
    
    def _add_information_gathering(
        self,
        response: str,
        context: ConversationContext,
        persona_profile: PersonaProfile
    ) -> str:
        """
        Add information gathering elements to the response.
        
        Args:
            response: Current response
            context: Conversation context
            persona_profile: Persona profile
            
        Returns:
            str: Response with information gathering
        """
        # Add questions based on persona and turn number
        if context.turn_number <= 5 and random.random() < persona_profile.question_frequency:
            question_patterns = self.INFORMATION_GATHERING_PATTERNS.get(context.persona, [])
            if question_patterns:
                question = random.choice(question_patterns)
                
                # Fill question variables
                question = self._fill_template_variables(question, context)
                
                response += f" {question}"
        
        return response
    
    def _analyze_response_characteristics(
        self,
        response_content: str,
        persona: PersonaType
    ) -> Dict[str, Any]:
        """
        Analyze characteristics of the generated response.
        
        Args:
            response_content: Generated response
            persona: Persona type
            
        Returns:
            Dict[str, Any]: Response characteristics
        """
        return {
            'word_count': len(response_content.split()),
            'question_count': response_content.count('?'),
            'sentence_count': len(re.split(r'[.!?]+', response_content)),
            'technical_terms': len(re.findall(r'\b(?:upi|otp|cvv|api|technical|system)\b', response_content.lower())),
            'cautious_language': len(re.findall(r'\b(?:careful|worried|concerned|suspicious)\b', response_content.lower())),
            'persona': persona.value,
            'response_length': len(response_content)
        }
    
    def _generate_fallback_response(self, message_content: str, language: str = 'en') -> ResponseGenerationResult:
        """
        Generate a safe fallback response when persona-based generation fails.
        
        Args:
            message_content: Original message
            language: Response language
            
        Returns:
            ResponseGenerationResult: Fallback response
        """
        fallback_responses = {
            'en': [
                "Thank you for your message. I need some time to think about this.",
                "I received your message. Let me consider what you've said.",
                "Thanks for reaching out. I'll need to look into this further.",
                "I got your message. I want to make sure I understand everything correctly."
            ],
            'hi': [
                "आपके संदेश के लिए धन्यवाद। मुझे इसके बारे में सोचने का समय चाहिए।",
                "मुझे आपका संदेश मिल गया है। मैं आपकी बात पर विचार करूंगा।",
                "संपर्क करने के लिए धन्यवाद। मुझे इसकी और जांच करनी होगी।"
            ],
            'hinglish': [
                "Thank you for your message. Mujhe iske baare mein sochna hoga.",
                "Aapka message mil gaya hai. Main iske baare mein consider karunga.",
                "Thanks for reaching out. Mujhe isko further check karna hoga."
            ]
        }
        
        responses = fallback_responses.get(language, fallback_responses['en'])
        response_content = random.choice(responses)
        
        return ResponseGenerationResult(
            response_content=response_content,
            persona_consistency_score=0.5,
            response_characteristics={'fallback': True},
            generation_method="fallback",
            confidence=0.5,
            processing_time_ms=10
        )


# Global conversation engine instance
conversation_engine = ConversationEngine()