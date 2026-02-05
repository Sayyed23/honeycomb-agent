"""
Probabilistic agent activation system for intelligent scam engagement.

This module implements the core logic for deciding when and how to activate
AI agents based on risk scores, contextual factors, and probabilistic models.
"""

import random
import time
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Tuple, List
from dataclasses import dataclass
from enum import Enum
import logging
import hashlib

from app.core.logging import get_logger
from app.core.session_manager import session_manager, SessionState
from app.core.audit_logger import audit_logger
from app.core.persona_manager import persona_manager, PersonaType

logger = get_logger(__name__)


class ActivationDecision(Enum):
    """Agent activation decision outcomes."""
    ACTIVATE = "activate"
    NO_ACTIVATE = "no_activate"
    DEFER = "defer"


@dataclass
class ContextualFactors:
    """Contextual factors that influence activation decisions."""
    previous_engagements: int = 0
    time_since_last_engagement: Optional[int] = None  # seconds
    session_age: int = 0  # seconds
    conversation_turns: int = 0
    recent_activity_level: float = 0.0  # 0.0-1.0
    cross_session_patterns: bool = False
    temporal_anomalies: List[str] = None
    
    def __post_init__(self):
        if self.temporal_anomalies is None:
            self.temporal_anomalies = []


@dataclass
class ActivationResult:
    """Result of agent activation decision process."""
    decision: ActivationDecision
    persona: Optional[PersonaType]
    probability_used: float
    contextual_adjustments: Dict[str, float]
    reasoning: List[str]
    confidence: float
    response_template: Optional[str] = None


class AgentActivationEngine:
    """
    Probabilistic agent activation engine that decides when to engage scammers.
    
    Implements sophisticated decision-making based on:
    - Risk score thresholds (>0.50 for activation consideration)
    - Probabilistic engagement (70-95% activation rate)
    - Contextual adjustments for timing and previous engagements
    - Persona selection based on message characteristics
    """
    
    # Base activation probabilities for different risk score ranges
    BASE_ACTIVATION_PROBABILITIES = {
        (0.50, 0.60): 0.70,  # Medium risk, moderate confidence
        (0.60, 0.70): 0.75,  # Medium-high risk, good confidence
        (0.70, 0.80): 0.80,  # High risk, lower confidence
        (0.80, 0.85): 0.85,  # High risk, medium confidence
        (0.85, 0.90): 0.90,  # Very high risk, high confidence
        (0.90, 0.95): 0.93,  # Extreme risk, very high confidence
        (0.95, 1.00): 0.95   # Maximum risk, maximum confidence
    }
    
    # Non-engaging response templates by language
    NON_ENGAGING_RESPONSES = {
        'en': [
            "Thank you for your message. I'll get back to you when I can.",
            "I received your message. Let me think about it.",
            "Thanks for reaching out. I'll respond soon.",
            "I got your message. I'll need some time to consider it.",
            "Thanks for contacting me. I'll reply when possible.",
            "I see your message. Let me get back to you later.",
            "Received your message. I'll respond when I have time.",
            "Thank you for writing. I'll think about it and reply."
        ],
        'hi': [
            "आपके संदेश के लिए धन्यवाद। मैं जल्द ही जवाब दूंगा।",
            "मुझे आपका संदेश मिल गया है। मैं इसके बारे में सोचूंगा।",
            "संपर्क करने के लिए धन्यवाद। मैं जल्द ही जवाब दूंगा।",
            "आपका संदेश मिल गया। मैं समय मिलने पर जवाब दूंगा।",
            "मैंने आपका संदेश देखा है। बाद में जवाब दूंगा।",
            "संदेश के लिए धन्यवाद। मैं सोच कर बताऊंगा।"
        ],
        'hinglish': [
            "Thank you for your message. Main jaldi reply karunga.",
            "Aapka message mil gaya hai. Main sochke bataunga.",
            "Thanks for contacting. Main soon reply karunga.",
            "Message received. Main time milne par reply karunga.",
            "Aapka message dekha hai. Main baad mein reply karunga.",
            "Thanks for message. Main think karke bataunga."
        ]
    }
    
    def __init__(self):
        """Initialize the agent activation engine."""
        self.activation_history = {}  # Track activation history by session
        self.global_stats = {
            'total_activations': 0,
            'total_decisions': 0,
            'activation_rate': 0.0,
            'last_reset': datetime.utcnow()
        }
    
    async def should_activate_agent(
        self,
        session_id: str,
        risk_score: float,
        confidence: float,
        message_content: str,
        conversation_history: List[Dict[str, Any]] = None,
        metadata: Dict[str, Any] = None
    ) -> ActivationResult:
        """
        Determine whether to activate an agent for this session.
        
        Args:
            session_id: Unique session identifier
            risk_score: Risk score from scam detection (0.0-1.0)
            confidence: Confidence in risk assessment (0.0-1.0)
            message_content: Current message content
            conversation_history: Previous conversation messages
            metadata: Additional context metadata
            
        Returns:
            ActivationResult: Activation decision with reasoning
        """
        start_time = time.time()
        
        if conversation_history is None:
            conversation_history = []
        if metadata is None:
            metadata = {}
        
        try:
            # Get session state for contextual factors
            session_state = await session_manager.get_session(session_id)
            contextual_factors = await self._analyze_contextual_factors(
                session_id, session_state, conversation_history
            )
            
            # Check if risk score meets activation threshold (lowered for better engagement)
            if risk_score < 0.50:
                return await self._create_no_activation_result(
                    risk_score, confidence, contextual_factors,
                    reason="risk_score_below_threshold",
                    language=metadata.get('language', 'en')
                )
            
            # Calculate base activation probability
            base_probability = self._calculate_base_probability(risk_score, confidence)
            
            # Apply contextual adjustments
            adjusted_probability, adjustments = self._apply_contextual_adjustments(
                base_probability, contextual_factors, session_state
            )
            
            # Make probabilistic decision
            random_value = random.random()
            should_activate = random_value < adjusted_probability
            
            # Select persona if activating
            persona = None
            if should_activate:
                persona, persona_confidence = await persona_manager.select_persona(
                    session_id, message_content, risk_score, confidence, conversation_history, metadata
                )
                
                # Update session with selected persona
                await session_manager.activate_agent(session_id, persona.value)
            
            # Create reasoning
            reasoning = self._generate_reasoning(
                risk_score, confidence, base_probability, adjusted_probability,
                contextual_factors, should_activate, random_value
            )
            
            # Update statistics
            self._update_activation_stats(should_activate)
            
            # Record activation history
            await self._record_activation_decision(
                session_id, should_activate, adjusted_probability, persona, reasoning
            )
            
            # Calculate processing time
            processing_time_ms = int((time.time() - start_time) * 1000)
            
            # Log comprehensive audit event
            audit_event_id = audit_logger.log_agent_activation_decision(
                session_id=session_id,
                risk_score=risk_score,
                confidence=confidence,
                base_probability=base_probability,
                adjusted_probability=adjusted_probability,
                contextual_adjustments=adjustments,
                decision=ActivationDecision.ACTIVATE if should_activate else ActivationDecision.NO_ACTIVATE,
                selected_persona=persona.value if persona else None,
                reasoning=reasoning,
                random_value=random_value,
                contextual_factors=contextual_factors.__dict__,
                processing_time_ms=processing_time_ms,
                correlation_id=metadata.get('correlation_id')
            )
            
            logger.info(
                "Agent activation decision completed",
                extra={
                    "audit_event_id": audit_event_id,
                    "session_id": session_id,
                    "risk_score": risk_score,
                    "confidence": confidence,
                    "decision": "activate" if should_activate else "no_activate",
                    "probability": adjusted_probability,
                    "persona": persona.value if persona else None,
                    "processing_time_ms": processing_time_ms
                }
            )
            
            if should_activate:
                return ActivationResult(
                    decision=ActivationDecision.ACTIVATE,
                    persona=persona,
                    probability_used=adjusted_probability,
                    contextual_adjustments=adjustments,
                    reasoning=reasoning,
                    confidence=confidence
                )
            else:
                return await self._create_no_activation_result(
                    risk_score, confidence, contextual_factors,
                    reason="probabilistic_decision",
                    language=metadata.get('language', 'en'),
                    probability_used=adjusted_probability,
                    adjustments=adjustments,
                    reasoning=reasoning
                )
                
        except Exception as e:
            logger.error(f"Error in agent activation decision: {e}", exc_info=True)
            
            # Log error audit event
            audit_logger.log_system_error(
                error_type="agent_activation_error",
                error_message=f"Error in agent activation decision: {e}",
                error_details={
                    "session_id": session_id,
                    "risk_score": risk_score,
                    "confidence": confidence,
                    "processing_time_ms": int((time.time() - start_time) * 1000)
                },
                session_id=session_id,
                correlation_id=metadata.get('correlation_id')
            )
            
            # Return safe default (no activation)
            return await self._create_no_activation_result(
                risk_score, confidence, ContextualFactors(),
                reason="system_error",
                language=metadata.get('language', 'en')
            )
    
    async def _analyze_contextual_factors(
        self,
        session_id: str,
        session_state: Optional[SessionState],
        conversation_history: List[Dict[str, Any]]
    ) -> ContextualFactors:
        """
        Analyze contextual factors that influence activation decisions.
        
        Args:
            session_id: Session identifier
            session_state: Current session state
            conversation_history: Conversation history
            
        Returns:
            ContextualFactors: Analyzed contextual factors
        """
        factors = ContextualFactors()
        
        if session_state:
            # Calculate session age
            if session_state.metrics.start_time:
                session_age = (datetime.utcnow() - session_state.metrics.start_time).total_seconds()
                factors.session_age = int(session_age)
            
            # Get conversation turns
            factors.conversation_turns = session_state.metrics.total_turns
            
            # Check if agent was previously activated
            factors.previous_engagements = 1 if session_state.metrics.agent_activated else 0
            
            # Calculate time since last activity
            if session_state.metrics.last_activity:
                time_since_last = (datetime.utcnow() - session_state.metrics.last_activity).total_seconds()
                factors.time_since_last_engagement = int(time_since_last)
        
        # Analyze recent activity level from conversation history
        if conversation_history:
            factors.recent_activity_level = self._calculate_activity_level(conversation_history)
            factors.temporal_anomalies = self._detect_temporal_anomalies(conversation_history)
        
        # Check for cross-session patterns (simplified for now)
        factors.cross_session_patterns = await self._check_cross_session_patterns(session_id)
        
        return factors
    
    def _calculate_base_probability(self, risk_score: float, confidence: float) -> float:
        """
        Calculate base activation probability based on risk score and confidence.
        
        Args:
            risk_score: Risk score (0.0-1.0)
            confidence: Confidence level (0.0-1.0)
            
        Returns:
            float: Base activation probability
        """
        # Find appropriate probability range
        for (min_score, max_score), base_prob in self.BASE_ACTIVATION_PROBABILITIES.items():
            if min_score <= risk_score < max_score:
                # Interpolate within the range based on exact score
                range_position = (risk_score - min_score) / (max_score - min_score)
                
                # Get next range for interpolation
                next_ranges = [
                    (r, p) for (r, p) in self.BASE_ACTIVATION_PROBABILITIES.items()
                    if r[0] > max_score
                ]
                
                if next_ranges:
                    next_prob = next_ranges[0][1]
                    interpolated_prob = base_prob + (next_prob - base_prob) * range_position
                else:
                    interpolated_prob = base_prob
                
                # Adjust based on confidence
                confidence_adjustment = (confidence - 0.5) * 0.1  # ±5% based on confidence
                final_prob = interpolated_prob + confidence_adjustment
                
                return max(0.75, min(0.95, final_prob))  # Ensure within bounds
        
        # Fallback for edge cases
        return 0.95 if risk_score >= 0.95 else 0.70  # Increased fallback probability
    
    def _apply_contextual_adjustments(
        self,
        base_probability: float,
        contextual_factors: ContextualFactors,
        session_state: Optional[SessionState]
    ) -> Tuple[float, Dict[str, float]]:
        """
        Apply contextual adjustments to base activation probability.
        
        Args:
            base_probability: Base activation probability
            contextual_factors: Contextual factors
            session_state: Session state
            
        Returns:
            Tuple[float, Dict[str, float]]: (adjusted_probability, adjustments)
        """
        adjustments = {}
        adjusted_probability = base_probability
        
        # Previous engagement adjustment
        if contextual_factors.previous_engagements > 0:
            # Reduce probability for sessions that already had agent activation
            engagement_penalty = min(0.3, contextual_factors.previous_engagements * 0.15)
            adjustments['previous_engagements'] = -engagement_penalty
            adjusted_probability *= (1.0 - engagement_penalty)
        
        # Time-based adjustments
        if contextual_factors.time_since_last_engagement is not None:
            time_hours = contextual_factors.time_since_last_engagement / 3600.0
            
            if time_hours < 1.0:  # Less than 1 hour
                # Significant reduction for recent activity
                time_penalty = 0.4
                adjustments['recent_activity'] = -time_penalty
                adjusted_probability *= (1.0 - time_penalty)
            elif time_hours < 6.0:  # Less than 6 hours
                # Moderate reduction
                time_penalty = 0.2
                adjustments['moderate_recent_activity'] = -time_penalty
                adjusted_probability *= (1.0 - time_penalty)
            elif time_hours > 24.0:  # More than 24 hours
                # Slight boost for old sessions
                time_boost = 0.1
                adjustments['old_session_boost'] = time_boost
                adjusted_probability *= (1.0 + time_boost)
        
        # Session age adjustments
        if contextual_factors.session_age > 0:
            age_hours = contextual_factors.session_age / 3600.0
            
            if age_hours > 2.0:  # Long-running session
                # Reduce probability for very long sessions
                age_penalty = min(0.2, (age_hours - 2.0) * 0.05)
                adjustments['long_session_penalty'] = -age_penalty
                adjusted_probability *= (1.0 - age_penalty)
        
        # Conversation turn adjustments
        if contextual_factors.conversation_turns > 5:
            # Reduce probability for sessions with many turns
            turn_penalty = min(0.25, (contextual_factors.conversation_turns - 5) * 0.03)
            adjustments['high_turn_penalty'] = -turn_penalty
            adjusted_probability *= (1.0 - turn_penalty)
        elif contextual_factors.conversation_turns == 0:
            # Slight boost for first interaction
            first_interaction_boost = 0.05
            adjustments['first_interaction_boost'] = first_interaction_boost
            adjusted_probability *= (1.0 + first_interaction_boost)
        
        # Activity level adjustments
        if contextual_factors.recent_activity_level > 0.8:
            # High activity might indicate automated behavior
            activity_penalty = 0.15
            adjustments['high_activity_penalty'] = -activity_penalty
            adjusted_probability *= (1.0 - activity_penalty)
        elif contextual_factors.recent_activity_level < 0.3:
            # Low activity might indicate more genuine interaction
            activity_boost = 0.1
            adjustments['low_activity_boost'] = activity_boost
            adjusted_probability *= (1.0 + activity_boost)
        
        # Temporal anomaly adjustments
        if contextual_factors.temporal_anomalies:
            if 'rapid_fire_messaging' in contextual_factors.temporal_anomalies:
                rapid_penalty = 0.2
                adjustments['rapid_messaging_penalty'] = -rapid_penalty
                adjusted_probability *= (1.0 - rapid_penalty)
            
            if 'suspicious_timing' in contextual_factors.temporal_anomalies:
                timing_penalty = 0.15
                adjustments['suspicious_timing_penalty'] = -timing_penalty
                adjusted_probability *= (1.0 - timing_penalty)
        
        # Cross-session pattern adjustments
        if contextual_factors.cross_session_patterns:
            # Boost for patterns that match known scam behaviors
            pattern_boost = 0.1
            adjustments['cross_session_pattern_boost'] = pattern_boost
            adjusted_probability *= (1.0 + pattern_boost)
        
        # Global activation rate balancing
        current_rate = self.global_stats.get('activation_rate', 0.0)
        target_rate = 0.875  # Target 87.5% activation rate (middle of 80-95% range)
        
        if current_rate > 0.92:  # Too high activation rate
            rate_penalty = 0.1
            adjustments['global_rate_balancing'] = -rate_penalty
            adjusted_probability *= (1.0 - rate_penalty)
        elif current_rate < 0.83:  # Too low activation rate
            rate_boost = 0.1
            adjustments['global_rate_balancing'] = rate_boost
            adjusted_probability *= (1.0 + rate_boost)
        
        # Ensure probability stays within valid bounds
        adjusted_probability = max(0.75, min(0.95, adjusted_probability))
        
        return adjusted_probability, adjustments
    
    def _calculate_activity_level(self, conversation_history: List[Dict[str, Any]]) -> float:
        """
        Calculate recent activity level from conversation history.
        
        Args:
            conversation_history: Conversation messages
            
        Returns:
            float: Activity level (0.0-1.0)
        """
        if not conversation_history:
            return 0.0
        
        # Look at recent messages (last 5 or all if fewer)
        recent_messages = conversation_history[-5:]
        
        # Calculate message frequency
        if len(recent_messages) < 2:
            return 0.5  # Neutral for single message
        
        # Parse timestamps and calculate intervals
        timestamps = []
        for msg in recent_messages:
            timestamp = msg.get('timestamp')
            if isinstance(timestamp, str):
                try:
                    timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                except:
                    timestamp = datetime.utcnow()
            elif not isinstance(timestamp, datetime):
                timestamp = datetime.utcnow()
            timestamps.append(timestamp)
        
        # Calculate average time between messages
        intervals = []
        for i in range(1, len(timestamps)):
            interval = (timestamps[i] - timestamps[i-1]).total_seconds()
            intervals.append(interval)
        
        if not intervals:
            return 0.5
        
        avg_interval = sum(intervals) / len(intervals)
        
        # Convert to activity level (inverse relationship)
        # Very fast responses (< 30 seconds) = high activity (0.8-1.0)
        # Normal responses (30-300 seconds) = medium activity (0.3-0.7)
        # Slow responses (> 300 seconds) = low activity (0.0-0.3)
        
        if avg_interval < 30:
            return 0.9
        elif avg_interval < 60:
            return 0.7
        elif avg_interval < 180:
            return 0.5
        elif avg_interval < 300:
            return 0.3
        else:
            return 0.1
    
    def _detect_temporal_anomalies(self, conversation_history: List[Dict[str, Any]]) -> List[str]:
        """
        Detect temporal anomalies in conversation patterns.
        
        Args:
            conversation_history: Conversation messages
            
        Returns:
            List[str]: Detected anomalies
        """
        anomalies = []
        
        if len(conversation_history) < 3:
            return anomalies
        
        # Check for rapid-fire messaging
        rapid_responses = 0
        for i in range(1, len(conversation_history)):
            prev_msg = conversation_history[i-1]
            curr_msg = conversation_history[i]
            
            # Parse timestamps
            prev_time = prev_msg.get('timestamp')
            curr_time = curr_msg.get('timestamp')
            
            if isinstance(prev_time, str):
                try:
                    prev_time = datetime.fromisoformat(prev_time.replace('Z', '+00:00'))
                except:
                    continue
            
            if isinstance(curr_time, str):
                try:
                    curr_time = datetime.fromisoformat(curr_time.replace('Z', '+00:00'))
                except:
                    continue
            
            if isinstance(prev_time, datetime) and isinstance(curr_time, datetime):
                time_diff = (curr_time - prev_time).total_seconds()
                if time_diff < 10:  # Less than 10 seconds
                    rapid_responses += 1
        
        if rapid_responses >= 2:
            anomalies.append('rapid_fire_messaging')
        
        # Check for suspicious timing patterns
        if len(conversation_history) >= 4:
            # Check if all responses are suspiciously consistent
            intervals = []
            for i in range(1, len(conversation_history)):
                prev_msg = conversation_history[i-1]
                curr_msg = conversation_history[i]
                
                prev_time = prev_msg.get('timestamp')
                curr_time = curr_msg.get('timestamp')
                
                if isinstance(prev_time, str):
                    try:
                        prev_time = datetime.fromisoformat(prev_time.replace('Z', '+00:00'))
                    except:
                        continue
                
                if isinstance(curr_time, str):
                    try:
                        curr_time = datetime.fromisoformat(curr_time.replace('Z', '+00:00'))
                    except:
                        continue
                
                if isinstance(prev_time, datetime) and isinstance(curr_time, datetime):
                    interval = (curr_time - prev_time).total_seconds()
                    intervals.append(interval)
            
            if len(intervals) >= 3:
                # Check for suspiciously consistent intervals (potential bot)
                avg_interval = sum(intervals) / len(intervals)
                variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
                
                if variance < 25 and avg_interval < 60:  # Very consistent and fast
                    anomalies.append('suspicious_timing')
        
        return anomalies
    
    async def _check_cross_session_patterns(self, session_id: str) -> bool:
        """
        Check for cross-session patterns (simplified implementation).
        
        Args:
            session_id: Current session ID
            
        Returns:
            bool: True if cross-session patterns detected
        """
        # For now, implement a simple hash-based check
        # In production, this would query the database for similar sessions
        
        session_hash = hashlib.md5(session_id.encode()).hexdigest()
        
        # Simple pattern: if session ID has certain characteristics
        # This is a placeholder - real implementation would check database
        return len(session_hash) > 20 and 'a' in session_hash[:5]
    
    def _generate_reasoning(
        self,
        risk_score: float,
        confidence: float,
        base_probability: float,
        adjusted_probability: float,
        contextual_factors: ContextualFactors,
        should_activate: bool,
        random_value: float
    ) -> List[str]:
        """
        Generate human-readable reasoning for the activation decision.
        
        Args:
            risk_score: Risk score
            confidence: Confidence level
            base_probability: Base activation probability
            adjusted_probability: Final adjusted probability
            contextual_factors: Contextual factors
            should_activate: Final activation decision
            random_value: Random value used for decision
            
        Returns:
            List[str]: Reasoning steps
        """
        reasoning = []
        
        # Risk score reasoning
        if risk_score >= 0.95:
            reasoning.append(f"Extremely high risk score ({risk_score:.3f}) indicates very likely scam")
        elif risk_score >= 0.85:
            reasoning.append(f"Very high risk score ({risk_score:.3f}) indicates likely scam")
        elif risk_score >= 0.70:
            reasoning.append(f"High risk score ({risk_score:.3f}) meets activation threshold")
        elif risk_score >= 0.50:
            reasoning.append(f"Medium risk score ({risk_score:.3f}) meets activation threshold")
        
        # Confidence reasoning
        if confidence >= 0.8:
            reasoning.append(f"High confidence ({confidence:.3f}) in risk assessment")
        elif confidence >= 0.6:
            reasoning.append(f"Medium confidence ({confidence:.3f}) in risk assessment")
        else:
            reasoning.append(f"Lower confidence ({confidence:.3f}) in risk assessment")
        
        # Base probability reasoning
        reasoning.append(f"Base activation probability: {base_probability:.3f}")
        
        # Contextual adjustments reasoning
        if contextual_factors.previous_engagements > 0:
            reasoning.append(f"Previous engagements ({contextual_factors.previous_engagements}) reduce probability")
        
        if contextual_factors.time_since_last_engagement is not None:
            hours = contextual_factors.time_since_last_engagement / 3600.0
            if hours < 1:
                reasoning.append(f"Recent activity ({hours:.1f}h ago) significantly reduces probability")
            elif hours < 6:
                reasoning.append(f"Moderate recent activity ({hours:.1f}h ago) reduces probability")
        
        if contextual_factors.conversation_turns > 5:
            reasoning.append(f"High turn count ({contextual_factors.conversation_turns}) reduces probability")
        
        if contextual_factors.temporal_anomalies:
            reasoning.append(f"Temporal anomalies detected: {', '.join(contextual_factors.temporal_anomalies)}")
        
        # Final decision reasoning
        reasoning.append(f"Final adjusted probability: {adjusted_probability:.3f}")
        reasoning.append(f"Random value: {random_value:.3f}")
        
        if should_activate:
            reasoning.append(f"Decision: ACTIVATE (random {random_value:.3f} < probability {adjusted_probability:.3f})")
        else:
            reasoning.append(f"Decision: NO ACTIVATE (random {random_value:.3f} >= probability {adjusted_probability:.3f})")
        
        return reasoning
    
    def _update_activation_stats(self, activated: bool) -> None:
        """
        Update global activation statistics.
        
        Args:
            activated: Whether agent was activated
        """
        self.global_stats['total_decisions'] += 1
        if activated:
            self.global_stats['total_activations'] += 1
        
        # Calculate current activation rate
        if self.global_stats['total_decisions'] > 0:
            self.global_stats['activation_rate'] = (
                self.global_stats['total_activations'] / self.global_stats['total_decisions']
            )
        
        # Reset stats periodically to avoid stale data
        now = datetime.utcnow()
        if (now - self.global_stats['last_reset']).total_seconds() > 86400:  # 24 hours
            self.global_stats = {
                'total_activations': 1 if activated else 0,
                'total_decisions': 1,
                'activation_rate': 1.0 if activated else 0.0,
                'last_reset': now
            }
    
    async def _record_activation_decision(
        self,
        session_id: str,
        activated: bool,
        probability: float,
        persona: Optional[PersonaType],
        reasoning: List[str]
    ) -> None:
        """
        Record activation decision in session history.
        
        Args:
            session_id: Session identifier
            activated: Whether agent was activated
            probability: Activation probability used
            persona: Selected persona (if activated)
            reasoning: Decision reasoning
        """
        decision_record = {
            'timestamp': datetime.utcnow().isoformat(),
            'activated': activated,
            'probability': probability,
            'persona': persona.value if persona else None,
            'reasoning': reasoning
        }
        
        if session_id not in self.activation_history:
            self.activation_history[session_id] = []
        
        self.activation_history[session_id].append(decision_record)
        
        # Keep only recent decisions (last 10)
        if len(self.activation_history[session_id]) > 10:
            self.activation_history[session_id] = self.activation_history[session_id][-10:]
    
    async def _create_no_activation_result(
        self,
        risk_score: float,
        confidence: float,
        contextual_factors: ContextualFactors,
        reason: str,
        language: str = 'en',
        probability_used: float = 0.0,
        adjustments: Dict[str, float] = None,
        reasoning: List[str] = None
    ) -> ActivationResult:
        """
        Create a no-activation result with appropriate response template.
        
        Args:
            risk_score: Risk score
            confidence: Confidence level
            contextual_factors: Contextual factors
            reason: Reason for no activation
            language: Response language
            probability_used: Probability used (if applicable)
            adjustments: Contextual adjustments (if applicable)
            reasoning: Decision reasoning (if applicable)
            
        Returns:
            ActivationResult: No activation result
        """
        if adjustments is None:
            adjustments = {}
        if reasoning is None:
            reasoning = [f"No activation: {reason}"]
        
        # Select appropriate non-engaging response
        response_templates = self.NON_ENGAGING_RESPONSES.get(language, self.NON_ENGAGING_RESPONSES['en'])
        response_template = random.choice(response_templates)
        
        return ActivationResult(
            decision=ActivationDecision.NO_ACTIVATE,
            persona=None,
            probability_used=probability_used,
            contextual_adjustments=adjustments,
            reasoning=reasoning,
            confidence=confidence,
            response_template=response_template
        )
    
    def get_activation_statistics(self) -> Dict[str, Any]:
        """
        Get current activation statistics.
        
        Returns:
            Dict[str, Any]: Activation statistics
        """
        return {
            'total_decisions': self.global_stats['total_decisions'],
            'total_activations': self.global_stats['total_activations'],
            'activation_rate': self.global_stats['activation_rate'],
            'target_rate_range': '80-95%',
            'last_reset': self.global_stats['last_reset'].isoformat(),
            'within_target': 0.80 <= self.global_stats['activation_rate'] <= 0.95
        }


# Global agent activation engine instance
agent_activation_engine = AgentActivationEngine()