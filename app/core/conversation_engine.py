"""
Conversation engine for persona-based response generation and consistency tracking.

This module implements the conversation management system that generates
persona-consistent responses and tracks conversation state across multiple turns.
"""

import re
import time
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass
import logging
import random

from app.core.logging import get_logger
from app.core.persona_manager import persona_manager, PersonaType, PersonaProfile
from app.core.session_manager import session_manager
from app.core.audit_logger import audit_logger

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
class ResponseGenerationResult:
    """Result of response generation process."""
    response_content: str
    persona_consistency_score: float
    response_characteristics: Dict[str, Any]
    generation_method: str
    confidence: float
    processing_time_ms: int


class ConversationEngine:
    """
    Persona-based conversation engine for intelligent scammer engagement.
    
    Generates contextually appropriate responses that maintain persona consistency
    across conversation turns while gathering intelligence from scammers.
    """
    
    # Response templates by persona and context
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
        self.response_cache = {}  # Cache for similar responses
        self.conversation_patterns = {}  # Track conversation patterns
    
    async def generate_response(
        self,
        session_id: str,
        message_content: str,
        conversation_history: List[Dict[str, Any]] = None,
        metadata: Dict[str, Any] = None
    ) -> ResponseGenerationResult:
        """
        Generate a persona-consistent response to the given message.
        
        Args:
            session_id: Session identifier
            message_content: Current message content
            conversation_history: Previous conversation messages
            metadata: Additional context metadata
            
        Returns:
            ResponseGenerationResult: Generated response with metadata
        """
        start_time = time.time()
        
        if conversation_history is None:
            conversation_history = []
        if metadata is None:
            metadata = {}
        
        try:
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
                turn_number=len(conversation_history) + 1,
                language=metadata.get('language', 'en'),
                metadata=metadata
            )
            
            # Generate response based on context and persona
            response_content = await self._generate_persona_response(context)
            
            # Track persona consistency
            consistency_score = await persona_manager.track_response_consistency(
                session_id, response_content, persona
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
                generation_method="persona_based",
                confidence=consistency_score,
                processing_time_ms=processing_time_ms
            )
            
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
                f"Generated persona response",
                extra={
                    "session_id": session_id,
                    "persona": persona.value,
                    "consistency_score": consistency_score,
                    "processing_time_ms": processing_time_ms
                }
            )
            
            return result
            
        except Exception as e:
            logger.error(f"Error generating response: {e}", exc_info=True)
            
            # Log error
            audit_logger.log_system_error(
                error_type="response_generation_error",
                error_message=f"Error generating response: {e}",
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
    
    async def _generate_persona_response(self, context: ConversationContext) -> str:
        """
        Generate a response based on persona characteristics and context.
        
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