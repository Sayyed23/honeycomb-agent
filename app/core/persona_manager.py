"""
Persona selection and management system for intelligent agent engagement.

This module implements sophisticated persona selection algorithms, consistency tracking,
and persona-specific response characteristics for realistic scammer engagement.
"""

import re
import time
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field
from enum import Enum
import logging
from collections import defaultdict, Counter

from app.core.logging import get_logger
from app.core.session_manager import session_manager
from app.core.audit_logger import audit_logger

logger = get_logger(__name__)


class PersonaType(Enum):
    """Available agent personas for engagement."""
    DIGITALLY_NAIVE = "digitally_naive"
    AVERAGE_USER = "average_user"
    SKEPTICAL = "skeptical"


class PersonaCharacteristic(Enum):
    """Persona characteristics for consistency tracking."""
    TECH_KNOWLEDGE = "tech_knowledge"
    TRUST_LEVEL = "trust_level"
    SKEPTICISM_LEVEL = "skepticism_level"
    COMMUNICATION_STYLE = "communication_style"
    QUESTION_FREQUENCY = "question_frequency"
    EMOTIONAL_RESPONSE = "emotional_response"


@dataclass
class PersonaProfile:
    """Detailed persona profile with characteristics and response patterns."""
    persona_type: PersonaType
    tech_knowledge_level: float  # 0.0-1.0 (low to high)
    trust_level: float  # 0.0-1.0 (suspicious to trusting)
    skepticism_level: float  # 0.0-1.0 (accepting to skeptical)
    question_frequency: float  # 0.0-1.0 (few to many questions)
    emotional_responsiveness: float  # 0.0-1.0 (calm to reactive)
    
    # Response characteristics
    typical_response_length: Tuple[int, int]  # (min, max) words
    common_phrases: List[str] = field(default_factory=list)
    question_patterns: List[str] = field(default_factory=list)
    vocabulary_complexity: float = 0.5  # 0.0-1.0 (simple to complex)
    
    # Behavioral patterns
    information_sharing_willingness: float = 0.5  # 0.0-1.0
    authority_deference: float = 0.5  # 0.0-1.0
    urgency_susceptibility: float = 0.5  # 0.0-1.0


@dataclass
class PersonaConsistencyMetrics:
    """Metrics for tracking persona consistency across conversation turns."""
    persona_type: PersonaType
    consistency_scores: Dict[PersonaCharacteristic, List[float]] = field(default_factory=lambda: defaultdict(list))
    response_patterns: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    characteristic_violations: List[str] = field(default_factory=list)
    overall_consistency_score: float = 1.0
    last_updated: datetime = field(default_factory=datetime.utcnow)


@dataclass
class PersonaSelectionContext:
    """Context information for persona selection algorithm."""
    message_content: str
    risk_score: float
    confidence: float
    conversation_history: List[Dict[str, Any]]
    metadata: Dict[str, Any]
    
    # Derived characteristics
    technical_complexity: float = 0.0
    authority_claims: float = 0.0
    urgency_level: float = 0.0
    financial_complexity: float = 0.0
    social_engineering_sophistication: float = 0.0
    conversation_depth: int = 0


class PersonaManager:
    """
    Advanced persona selection and management system.
    
    Provides sophisticated persona selection based on message context,
    tracks persona consistency across conversation turns, and manages
    persona-specific response characteristics.
    """
    
    # Predefined persona profiles
    PERSONA_PROFILES = {
        PersonaType.DIGITALLY_NAIVE: PersonaProfile(
            persona_type=PersonaType.DIGITALLY_NAIVE,
            tech_knowledge_level=0.2,
            trust_level=0.8,
            skepticism_level=0.2,
            question_frequency=0.7,
            emotional_responsiveness=0.6,
            typical_response_length=(15, 40),
            common_phrases=[
                "I'm not very good with technology",
                "Can you help me understand?",
                "I'm not sure how this works",
                "Is this safe?",
                "I don't know much about computers",
                "Should I be worried?",
                "What does that mean?",
                "I'm confused"
            ],
            question_patterns=[
                "How do I {action}?",
                "What is {term}?",
                "Is it safe to {action}?",
                "Should I {action}?",
                "Can you explain {concept}?"
            ],
            vocabulary_complexity=0.3,
            information_sharing_willingness=0.7,
            authority_deference=0.8,
            urgency_susceptibility=0.7
        ),
        
        PersonaType.AVERAGE_USER: PersonaProfile(
            persona_type=PersonaType.AVERAGE_USER,
            tech_knowledge_level=0.5,
            trust_level=0.5,
            skepticism_level=0.5,
            question_frequency=0.5,
            emotional_responsiveness=0.4,
            typical_response_length=(20, 60),
            common_phrases=[
                "Let me think about this",
                "I need to check something",
                "That sounds interesting",
                "I'm not entirely sure",
                "Can you give me more details?",
                "I want to be careful",
                "Let me understand this better",
                "I have some questions"
            ],
            question_patterns=[
                "Can you tell me more about {topic}?",
                "How does {process} work?",
                "What are the risks of {action}?",
                "Why do you need {information}?",
                "Is there another way to {action}?"
            ],
            vocabulary_complexity=0.5,
            information_sharing_willingness=0.4,
            authority_deference=0.5,
            urgency_susceptibility=0.4
        ),
        
        PersonaType.SKEPTICAL: PersonaProfile(
            persona_type=PersonaType.SKEPTICAL,
            tech_knowledge_level=0.8,
            trust_level=0.2,
            skepticism_level=0.8,
            question_frequency=0.8,
            emotional_responsiveness=0.3,
            typical_response_length=(25, 80),
            common_phrases=[
                "I need to verify this",
                "This doesn't sound right",
                "Can you prove that?",
                "I'm suspicious of this",
                "Show me evidence",
                "I don't trust this",
                "This seems like a scam",
                "I need more information"
            ],
            question_patterns=[
                "How can I verify {claim}?",
                "What proof do you have of {statement}?",
                "Why should I trust {source}?",
                "What's your real motive for {action}?",
                "Can you provide official documentation for {claim}?"
            ],
            vocabulary_complexity=0.7,
            information_sharing_willingness=0.2,
            authority_deference=0.2,
            urgency_susceptibility=0.2
        )
    }
    
    # Persona selection weights for different message characteristics
    SELECTION_WEIGHTS = {
        'technical_complexity': {
            PersonaType.DIGITALLY_NAIVE: -0.3,  # Avoid for complex technical content
            PersonaType.AVERAGE_USER: 0.1,
            PersonaType.SKEPTICAL: 0.4
        },
        'authority_claims': {
            PersonaType.DIGITALLY_NAIVE: 0.3,   # More susceptible to authority
            PersonaType.AVERAGE_USER: 0.1,
            PersonaType.SKEPTICAL: -0.2
        },
        'urgency_level': {
            PersonaType.DIGITALLY_NAIVE: 0.4,   # More susceptible to urgency
            PersonaType.AVERAGE_USER: 0.0,
            PersonaType.SKEPTICAL: -0.3
        },
        'financial_complexity': {
            PersonaType.DIGITALLY_NAIVE: -0.2,  # Avoid complex financial scams
            PersonaType.AVERAGE_USER: 0.2,
            PersonaType.SKEPTICAL: 0.3
        },
        'social_engineering_sophistication': {
            PersonaType.DIGITALLY_NAIVE: -0.4,  # Avoid sophisticated attacks
            PersonaType.AVERAGE_USER: 0.0,
            PersonaType.SKEPTICAL: 0.5
        }
    }
    
    def __init__(self):
        """Initialize the persona manager."""
        self.consistency_tracking = {}  # session_id -> PersonaConsistencyMetrics
        self.selection_history = {}  # session_id -> List[persona_selections]
        
        # Compile regex patterns for efficiency
        self._compile_detection_patterns()
    
    def _compile_detection_patterns(self):
        """Compile regex patterns for message analysis."""
        self.technical_patterns = re.compile(
            r'\b(?:upi|netbanking|otp|cvv|api|server|database|technical|system|'
            r'software|app|application|algorithm|encryption|protocol|interface|'
            r'blockchain|cryptocurrency|digital|online|cyber|tech|IT)\b',
            re.IGNORECASE
        )
        
        self.authority_patterns = re.compile(
            r'\b(?:officer|manager|executive|representative|agent|official|'
            r'government|bank|police|legal|authority|department|ministry|'
            r'commission|bureau|agency|administrator|supervisor)\b',
            re.IGNORECASE
        )
        
        self.urgency_patterns = re.compile(
            r'\b(?:urgent|immediately|asap|emergency|quick|fast|hurry|rush|'
            r'limited time|expires|deadline|now|today|instant|critical|'
            r'time sensitive|act now|don\'t delay)\b',
            re.IGNORECASE
        )
        
        self.financial_patterns = re.compile(
            r'\b(?:investment|trading|crypto|bitcoin|stock|mutual fund|insurance|'
            r'loan|credit|interest|profit|return|dividend|portfolio|asset|'
            r'financial|money|cash|payment|transfer|account|balance)\b',
            re.IGNORECASE
        )
        
        self.social_engineering_patterns = re.compile(
            r'\b(?:trust|verify|confirm|validate|secure|protect|safety|risk|'
            r'threat|danger|suspicious|fraud|scam|legitimate|authorized|'
            r'confidential|private|personal|sensitive)\b',
            re.IGNORECASE
        )
    
    async def select_persona(
        self,
        session_id: str,
        message_content: str,
        risk_score: float,
        confidence: float,
        conversation_history: List[Dict[str, Any]] = None,
        metadata: Dict[str, Any] = None
    ) -> Tuple[PersonaType, float]:
        """
        Select the most appropriate persona based on message context and history.
        
        Args:
            session_id: Unique session identifier
            message_content: Current message content
            risk_score: Risk score from scam detection
            confidence: Confidence in risk assessment
            conversation_history: Previous conversation messages
            metadata: Additional context metadata
            
        Returns:
            Tuple[PersonaType, float]: (selected_persona, selection_confidence)
        """
        start_time = time.time()
        
        if conversation_history is None:
            conversation_history = []
        if metadata is None:
            metadata = {}
        
        try:
            # Create selection context
            context = await self._analyze_selection_context(
                message_content, risk_score, confidence, conversation_history, metadata
            )
            
            # Check for existing persona consistency
            existing_persona = await self._get_existing_persona(session_id)
            if existing_persona:
                # Evaluate if we should maintain consistency or switch
                should_maintain, consistency_score = await self._evaluate_persona_consistency(
                    session_id, existing_persona, context
                )
                
                if should_maintain and consistency_score > 0.7:
                    logger.info(
                        f"Maintaining existing persona for consistency",
                        extra={
                            "session_id": session_id,
                            "persona": existing_persona.value,
                            "consistency_score": consistency_score
                        }
                    )
                    return existing_persona, consistency_score
            
            # Calculate persona scores
            persona_scores = self._calculate_persona_scores(context)
            
            # Select best persona
            selected_persona = max(persona_scores.keys(), key=lambda p: persona_scores[p])
            selection_confidence = persona_scores[selected_persona]
            
            # Normalize confidence to 0.0-1.0 range
            max_score = max(persona_scores.values())
            min_score = min(persona_scores.values())
            if max_score > min_score:
                normalized_confidence = (selection_confidence - min_score) / (max_score - min_score)
            else:
                normalized_confidence = 1.0
            
            # Initialize consistency tracking for new persona
            await self._initialize_persona_consistency(session_id, selected_persona)
            
            # Record selection history
            await self._record_persona_selection(
                session_id, selected_persona, context, persona_scores, normalized_confidence
            )
            
            # Calculate processing time
            processing_time_ms = int((time.time() - start_time) * 1000)
            
            # Log audit event
            audit_logger.log_persona_selection(
                session_id=session_id,
                selected_persona=selected_persona.value,
                selection_confidence=normalized_confidence,
                context_analysis=context.__dict__,
                persona_scores=persona_scores,
                processing_time_ms=processing_time_ms,
                correlation_id=metadata.get('correlation_id')
            )
            
            logger.info(
                f"Persona selected: {selected_persona.value}",
                extra={
                    "session_id": session_id,
                    "persona": selected_persona.value,
                    "confidence": normalized_confidence,
                    "processing_time_ms": processing_time_ms
                }
            )
            
            return selected_persona, normalized_confidence
            
        except Exception as e:
            logger.error(f"Error in persona selection: {e}", exc_info=True)
            
            # Log error audit event
            audit_logger.log_system_error(
                error_type="persona_selection_error",
                error_message=f"Error in persona selection: {e}",
                error_details={
                    "session_id": session_id,
                    "risk_score": risk_score,
                    "confidence": confidence
                },
                session_id=session_id,
                correlation_id=metadata.get('correlation_id')
            )
            
            # Return safe default
            return PersonaType.AVERAGE_USER, 0.5
    
    async def _analyze_selection_context(
        self,
        message_content: str,
        risk_score: float,
        confidence: float,
        conversation_history: List[Dict[str, Any]],
        metadata: Dict[str, Any]
    ) -> PersonaSelectionContext:
        """
        Analyze message context for persona selection.
        
        Args:
            message_content: Message content to analyze
            risk_score: Risk score
            confidence: Confidence level
            conversation_history: Conversation history
            metadata: Additional metadata
            
        Returns:
            PersonaSelectionContext: Analyzed context
        """
        context = PersonaSelectionContext(
            message_content=message_content,
            risk_score=risk_score,
            confidence=confidence,
            conversation_history=conversation_history,
            metadata=metadata,
            conversation_depth=len(conversation_history)
        )
        
        # Analyze technical complexity
        technical_matches = len(self.technical_patterns.findall(message_content))
        context.technical_complexity = min(1.0, technical_matches / 5.0)
        
        # Analyze authority claims
        authority_matches = len(self.authority_patterns.findall(message_content))
        context.authority_claims = min(1.0, authority_matches / 3.0)
        
        # Analyze urgency level
        urgency_matches = len(self.urgency_patterns.findall(message_content))
        context.urgency_level = min(1.0, urgency_matches / 4.0)
        
        # Analyze financial complexity
        financial_matches = len(self.financial_patterns.findall(message_content))
        context.financial_complexity = min(1.0, financial_matches / 5.0)
        
        # Analyze social engineering sophistication
        se_matches = len(self.social_engineering_patterns.findall(message_content))
        context.social_engineering_sophistication = min(1.0, se_matches / 6.0)
        
        return context
    
    def _calculate_persona_scores(self, context: PersonaSelectionContext) -> Dict[PersonaType, float]:
        """
        Calculate scores for each persona based on context.
        
        Args:
            context: Selection context
            
        Returns:
            Dict[PersonaType, float]: Persona scores
        """
        scores = {persona: 1.0 for persona in PersonaType}  # Base score
        
        # Apply characteristic-based weights
        characteristics = {
            'technical_complexity': context.technical_complexity,
            'authority_claims': context.authority_claims,
            'urgency_level': context.urgency_level,
            'financial_complexity': context.financial_complexity,
            'social_engineering_sophistication': context.social_engineering_sophistication
        }
        
        for characteristic, value in characteristics.items():
            if value > 0.1:  # Only apply if characteristic is present
                for persona in PersonaType:
                    weight = self.SELECTION_WEIGHTS[characteristic][persona]
                    scores[persona] += weight * value
        
        # Risk score adjustments
        if context.risk_score > 0.9:
            # Very high risk - prefer skeptical persona
            scores[PersonaType.SKEPTICAL] += 0.3
            scores[PersonaType.DIGITALLY_NAIVE] -= 0.2
        elif context.risk_score < 0.8:
            # Lower risk - prefer digitally naive for engagement
            scores[PersonaType.DIGITALLY_NAIVE] += 0.2
        
        # Conversation depth adjustments
        if context.conversation_depth > 5:
            # Long conversation - prefer average user for balance
            scores[PersonaType.AVERAGE_USER] += 0.2
        elif context.conversation_depth == 0:
            # First interaction - slight preference for digitally naive
            scores[PersonaType.DIGITALLY_NAIVE] += 0.1
        
        # Confidence adjustments
        if context.confidence > 0.8:
            # High confidence - can use more sophisticated personas
            scores[PersonaType.SKEPTICAL] += 0.1
        elif context.confidence < 0.6:
            # Lower confidence - prefer safer average user
            scores[PersonaType.AVERAGE_USER] += 0.2
        
        # Ensure all scores are positive
        min_score = min(scores.values())
        if min_score < 0:
            for persona in scores:
                scores[persona] -= min_score
        
        return scores
    
    async def _get_existing_persona(self, session_id: str) -> Optional[PersonaType]:
        """
        Get existing persona for session if any.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Optional[PersonaType]: Existing persona or None
        """
        try:
            session_state = await session_manager.get_session(session_id)
            if session_state and session_state.metrics.persona_type:
                return PersonaType(session_state.metrics.persona_type)
        except Exception as e:
            logger.warning(f"Error getting existing persona: {e}")
        
        return None
    
    async def _evaluate_persona_consistency(
        self,
        session_id: str,
        existing_persona: PersonaType,
        context: PersonaSelectionContext
    ) -> Tuple[bool, float]:
        """
        Evaluate whether to maintain persona consistency.
        
        Args:
            session_id: Session identifier
            existing_persona: Current persona
            context: Selection context
            
        Returns:
            Tuple[bool, float]: (should_maintain, consistency_score)
        """
        # Get consistency metrics
        consistency_metrics = self.consistency_tracking.get(session_id)
        if not consistency_metrics:
            return False, 0.0
        
        # Calculate current consistency score
        current_score = consistency_metrics.overall_consistency_score
        
        # Check if context strongly suggests different persona
        new_scores = self._calculate_persona_scores(context)
        existing_score = new_scores[existing_persona]
        max_score = max(new_scores.values())
        
        # If existing persona is still competitive, maintain consistency
        score_difference = max_score - existing_score
        
        if score_difference < 0.4 and current_score > 0.6:
            return True, current_score
        elif score_difference < 0.6 and current_score > 0.8:
            return True, current_score
        else:
            return False, current_score
    
    async def _initialize_persona_consistency(
        self,
        session_id: str,
        persona: PersonaType
    ) -> None:
        """
        Initialize persona consistency tracking for a session.
        
        Args:
            session_id: Session identifier
            persona: Selected persona
        """
        self.consistency_tracking[session_id] = PersonaConsistencyMetrics(
            persona_type=persona,
            consistency_scores=defaultdict(list),
            response_patterns=defaultdict(int),
            characteristic_violations=[],
            overall_consistency_score=1.0,
            last_updated=datetime.utcnow()
        )
    
    async def _record_persona_selection(
        self,
        session_id: str,
        persona: PersonaType,
        context: PersonaSelectionContext,
        scores: Dict[PersonaType, float],
        confidence: float
    ) -> None:
        """
        Record persona selection in history.
        
        Args:
            session_id: Session identifier
            persona: Selected persona
            context: Selection context
            scores: All persona scores
            confidence: Selection confidence
        """
        selection_record = {
            'timestamp': datetime.utcnow().isoformat(),
            'persona': persona.value,
            'confidence': confidence,
            'context': {
                'risk_score': context.risk_score,
                'technical_complexity': context.technical_complexity,
                'authority_claims': context.authority_claims,
                'urgency_level': context.urgency_level,
                'financial_complexity': context.financial_complexity,
                'conversation_depth': context.conversation_depth
            },
            'scores': {p.value: s for p, s in scores.items()}
        }
        
        if session_id not in self.selection_history:
            self.selection_history[session_id] = []
        
        self.selection_history[session_id].append(selection_record)
        
        # Keep only recent selections (last 10)
        if len(self.selection_history[session_id]) > 10:
            self.selection_history[session_id] = self.selection_history[session_id][-10:]
    
    async def track_response_consistency(
        self,
        session_id: str,
        response_content: str,
        persona: PersonaType
    ) -> float:
        """
        Track persona consistency in agent responses.
        
        Args:
            session_id: Session identifier
            response_content: Generated response content
            persona: Expected persona
            
        Returns:
            float: Consistency score (0.0-1.0)
        """
        try:
            consistency_metrics = self.consistency_tracking.get(session_id)
            if not consistency_metrics:
                await self._initialize_persona_consistency(session_id, persona)
                consistency_metrics = self.consistency_tracking[session_id]
            
            # Analyze response characteristics
            characteristics = self._analyze_response_characteristics(response_content, persona)
            
            # Update consistency scores
            for characteristic, score in characteristics.items():
                consistency_metrics.consistency_scores[characteristic].append(score)
                
                # Keep only recent scores (last 10)
                if len(consistency_metrics.consistency_scores[characteristic]) > 10:
                    consistency_metrics.consistency_scores[characteristic] = \
                        consistency_metrics.consistency_scores[characteristic][-10:]
            
            # Calculate overall consistency score
            overall_score = self._calculate_overall_consistency(consistency_metrics)
            consistency_metrics.overall_consistency_score = overall_score
            consistency_metrics.last_updated = datetime.utcnow()
            
            # Log consistency tracking
            logger.debug(
                f"Persona consistency tracked",
                extra={
                    "session_id": session_id,
                    "persona": persona.value,
                    "consistency_score": overall_score,
                    "characteristics": characteristics
                }
            )
            
            return overall_score
            
        except Exception as e:
            logger.error(f"Error tracking response consistency: {e}", exc_info=True)
            return 0.5  # Neutral score on error
    
    def _analyze_response_characteristics(
        self,
        response_content: str,
        persona: PersonaType
    ) -> Dict[PersonaCharacteristic, float]:
        """
        Analyze response characteristics against persona profile.
        
        Args:
            response_content: Response content to analyze
            persona: Expected persona
            
        Returns:
            Dict[PersonaCharacteristic, float]: Characteristic scores
        """
        profile = self.PERSONA_PROFILES[persona]
        characteristics = {}
        
        # Analyze tech knowledge level
        tech_terms = len(self.technical_patterns.findall(response_content))
        expected_tech = profile.tech_knowledge_level
        actual_tech = min(1.0, tech_terms / 3.0)
        characteristics[PersonaCharacteristic.TECH_KNOWLEDGE] = \
            1.0 - abs(expected_tech - actual_tech)
        
        # Analyze trust level (based on cautious language)
        cautious_words = len(re.findall(
            r'\b(?:careful|cautious|worried|concerned|suspicious|doubt|unsure|hesitant)\b',
            response_content, re.IGNORECASE
        ))
        expected_caution = 1.0 - profile.trust_level
        actual_caution = min(1.0, cautious_words / 2.0)
        characteristics[PersonaCharacteristic.TRUST_LEVEL] = \
            1.0 - abs(expected_caution - actual_caution)
        
        # Analyze skepticism level
        skeptical_words = len(re.findall(
            r'\b(?:prove|verify|evidence|doubt|question|suspicious|scam|fake)\b',
            response_content, re.IGNORECASE
        ))
        expected_skepticism = profile.skepticism_level
        actual_skepticism = min(1.0, skeptical_words / 2.0)
        characteristics[PersonaCharacteristic.SKEPTICISM_LEVEL] = \
            1.0 - abs(expected_skepticism - actual_skepticism)
        
        # Analyze question frequency
        questions = len(re.findall(r'\?', response_content))
        expected_questions_normalized = profile.question_frequency  # This is already 0.0-1.0
        actual_questions_normalized = min(1.0, questions / 3.0)  # Normalize to 0.0-1.0
        characteristics[PersonaCharacteristic.QUESTION_FREQUENCY] = \
            1.0 - abs(expected_questions_normalized - actual_questions_normalized)
        
        # Analyze communication style (response length)
        word_count = len(response_content.split())
        min_words, max_words = profile.typical_response_length
        if min_words <= word_count <= max_words:
            characteristics[PersonaCharacteristic.COMMUNICATION_STYLE] = 1.0
        else:
            # Calculate deviation from expected range
            if word_count < min_words:
                deviation = min(1.0, (min_words - word_count) / max(min_words, 1))
            else:
                deviation = min(1.0, (word_count - max_words) / max(max_words, 1))
            characteristics[PersonaCharacteristic.COMMUNICATION_STYLE] = \
                max(0.0, 1.0 - deviation)
        
        # Analyze emotional response
        emotional_words = len(re.findall(
            r'\b(?:excited|worried|scared|happy|angry|frustrated|confused|surprised)\b',
            response_content, re.IGNORECASE
        ))
        expected_emotion = profile.emotional_responsiveness
        actual_emotion = min(1.0, emotional_words / 2.0)
        characteristics[PersonaCharacteristic.EMOTIONAL_RESPONSE] = \
            1.0 - abs(expected_emotion - actual_emotion)
        
        return characteristics
    
    def _calculate_overall_consistency(
        self,
        consistency_metrics: PersonaConsistencyMetrics
    ) -> float:
        """
        Calculate overall consistency score from individual characteristics.
        
        Args:
            consistency_metrics: Consistency metrics
            
        Returns:
            float: Overall consistency score
        """
        if not consistency_metrics.consistency_scores:
            return 1.0
        
        # Calculate average score for each characteristic
        characteristic_averages = {}
        for characteristic, scores in consistency_metrics.consistency_scores.items():
            if scores:
                characteristic_averages[characteristic] = sum(scores) / len(scores)
        
        if not characteristic_averages:
            return 1.0
        
        # Weight different characteristics
        weights = {
            PersonaCharacteristic.TECH_KNOWLEDGE: 0.2,
            PersonaCharacteristic.TRUST_LEVEL: 0.2,
            PersonaCharacteristic.SKEPTICISM_LEVEL: 0.2,
            PersonaCharacteristic.COMMUNICATION_STYLE: 0.15,
            PersonaCharacteristic.QUESTION_FREQUENCY: 0.15,
            PersonaCharacteristic.EMOTIONAL_RESPONSE: 0.1
        }
        
        weighted_sum = 0.0
        total_weight = 0.0
        
        for characteristic, average_score in characteristic_averages.items():
            weight = weights.get(characteristic, 0.1)
            weighted_sum += average_score * weight
            total_weight += weight
        
        if total_weight > 0:
            return weighted_sum / total_weight
        else:
            return 1.0
    
    def get_persona_profile(self, persona: PersonaType) -> PersonaProfile:
        """
        Get detailed profile for a persona.
        
        Args:
            persona: Persona type
            
        Returns:
            PersonaProfile: Persona profile
        """
        return self.PERSONA_PROFILES[persona]
    
    def get_consistency_metrics(self, session_id: str) -> Optional[PersonaConsistencyMetrics]:
        """
        Get consistency metrics for a session.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Optional[PersonaConsistencyMetrics]: Consistency metrics or None
        """
        return self.consistency_tracking.get(session_id)
    
    def get_selection_history(self, session_id: str) -> List[Dict[str, Any]]:
        """
        Get persona selection history for a session.
        
        Args:
            session_id: Session identifier
            
        Returns:
            List[Dict[str, Any]]: Selection history
        """
        return self.selection_history.get(session_id, [])
    
    async def cleanup_session_data(self, session_id: str) -> None:
        """
        Clean up persona data for completed session.
        
        Args:
            session_id: Session identifier
        """
        self.consistency_tracking.pop(session_id, None)
        self.selection_history.pop(session_id, None)
        
        logger.debug(f"Cleaned up persona data for session {session_id}")


# Global persona manager instance
persona_manager = PersonaManager()