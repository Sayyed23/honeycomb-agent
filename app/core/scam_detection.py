"""
Scam detection engine for analyzing messages and calculating risk scores.
"""

import re
import json
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from enum import Enum
import logging
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import statistics
import time

from app.core.logging import get_logger
from app.core.ml_detection import MLScamDetector
from app.core.audit_logger import audit_logger

logger = get_logger(__name__)


class DetectionMethod(Enum):
    """Detection methods used for risk assessment."""
    RULE_BASED = "rule_based"
    KEYWORD_ANALYSIS = "keyword_analysis"
    PATTERN_MATCHING = "pattern_matching"
    CONTEXTUAL_ANALYSIS = "contextual_analysis"
    ML_CLASSIFICATION = "ml_classification"
    COMBINED = "combined"


@dataclass
class RiskAssessment:
    """Risk assessment result."""
    risk_score: float
    confidence: float
    detection_method: DetectionMethod
    risk_factors: List[str]
    details: Dict[str, Any]
    ml_prediction: Optional[Dict[str, Any]] = None


@dataclass
class TemporalPattern:
    """Temporal analysis result for conversation patterns."""
    message_frequency: float  # Messages per minute
    avg_response_time: float  # Average response time in seconds
    urgency_escalation: bool  # Whether urgency is escalating over time
    conversation_velocity: float  # Rate of conversation progression
    timing_anomalies: List[str]  # Detected timing anomalies


@dataclass
class ConversationFlow:
    """Analysis of conversation flow and progression."""
    topic_shifts: int  # Number of topic changes
    information_requests: int  # Number of information requests
    pressure_escalation: float  # Escalation score (0.0-1.0)
    engagement_tactics: List[str]  # Detected engagement tactics
    conversation_stage: str  # Current stage of conversation


@dataclass
class CrossSessionPattern:
    """Cross-session pattern analysis result."""
    similar_sessions: int  # Number of similar sessions found
    repeat_indicators: List[str]  # Indicators of repeat behavior
    entity_overlap: int  # Number of overlapping entities
    pattern_confidence: float  # Confidence in repeat detection


class ScamDetectionEngine:
    """
    Multi-layered scam detection engine that analyzes messages for scam indicators.
    
    Implements rule-based detection with keyword analysis and pattern matching
    to identify potential scam attempts.
    """
    
    # Financial keywords that indicate potential scams
    FINANCIAL_KEYWORDS = [
        # English
        'money', 'payment', 'transfer', 'bank', 'account', 'upi', 'paytm', 'gpay', 'phonepe',
        'cash', 'rupees', 'dollars', 'amount', 'fund', 'deposit', 'withdraw', 'transaction',
        'credit', 'debit', 'loan', 'investment', 'profit', 'earn', 'income', 'salary',
        'refund', 'reward', 'prize', 'lottery', 'winner', 'jackpot', 'bonus',
        'wallet', 'balance', 'card', 'atm', 'pin', 'otp', 'cvv', 'netbanking',
        'financial', 'finance', 'banking', 'pay', 'paid', 'paying', 'cost', 'price',
        'bill', 'invoice', 'receipt', 'charge', 'fee', 'commission',
        
        # Hindi (transliterated)
        'paisa', 'paise', 'rupaya', 'rupaye', 'bank', 'khata', 'account', 'transfer',
        'bhejiye', 'bhejo', 'send', 'karo', 'payment', 'transaction',
        'paise', 'dhan', 'sampatti', 'nivesh', 'faayda', 'labh',
        
        # Common UPI patterns
        'upi id', 'upi-id', 'upi_id', 'google pay', 'paytm number', 'phone pe',
        'bhim', 'amazon pay', 'mobikwik', 'freecharge'
    ]
    
    # Urgency indicators
    URGENCY_KEYWORDS = [
        # English
        'urgent', 'immediately', 'asap', 'emergency', 'quick', 'fast', 'hurry',
        'limited time', 'expires', 'deadline', 'last chance', 'act now',
        'don\'t delay', 'time sensitive', 'critical', 'important',
        'right now', 'instant', 'within', 'before', 'today only',
        'expires today', 'limited offer', 'hurry up', 'rush', 'quickly',
        
        # Hindi (transliterated)
        'turant', 'jaldi', 'abhi', 'emergency', 'urgent', 'important',
        'zaruri', 'jaldi karo', 'turant bhejo', 'abhi karo', 'der mat karo'
    ]
    
    # Social engineering patterns
    SOCIAL_ENGINEERING_KEYWORDS = [
        # Trust building
        'trust me', 'believe me', 'honest', 'genuine', 'legitimate', 'official',
        'authorized', 'verified', 'certified', 'government', 'bank official',
        'reliable', 'trustworthy', 'authentic', 'real', 'true',
        
        # Authority claims
        'manager', 'officer', 'executive', 'representative', 'agent', 'supervisor',
        'director', 'ceo', 'admin', 'support team', 'customer care',
        'customer service', 'technical support', 'help desk', 'security team',
        'fraud department', 'compliance', 'investigation', 'audit',
        
        # Fear tactics
        'blocked', 'suspended', 'cancelled', 'expired', 'deactivated', 'frozen',
        'penalty', 'fine', 'legal action', 'court', 'police', 'arrest',
        'lawsuit', 'criminal', 'fraud', 'investigation', 'report',
        'consequences', 'trouble', 'problem', 'issue', 'violation',
        
        # Hindi (transliterated)
        'bharosa', 'vishwas', 'sach', 'asli', 'officer', 'manager', 'sahab',
        'sarkari', 'adhikari', 'karmchari', 'band', 'block', 'samasyaa'
    ]
    
    # Contact information requests
    CONTACT_REQUEST_PATTERNS = [
        r'(?:send|share|give|provide|tell|show).*(?:number|phone|mobile|contact)',
        r'(?:your|apka|tumhara).*(?:number|phone|mobile|contact)',
        r'whatsapp.*number',
        r'mobile.*number',
        r'phone.*number',
        r'contact.*details',
        r'personal.*information',
        r'bank.*details',
        r'account.*number',
        r'card.*number',
        r'pin.*number',
        r'password',
        r'otp',
        r'cvv',
        r'expiry.*date',
        r'date.*birth',
        r'aadhar.*number',
        r'pan.*number',
        r'social.*security',
        r'address.*proof',
        r'id.*proof',
        r'verification.*code',
        r'security.*code',
        r'(?:share|send|give).*(?:details|info|information)',
        r'(?:what|kya).*(?:is|hai).*(?:your|tumhara|apka)',
        r'batao.*(?:number|details|account)',
        r'bolo.*(?:number|details|account)'
    ]
    
    # Suspicious patterns
    SUSPICIOUS_PATTERNS = [
        # Multiple exclamation marks or question marks
        r'[!]{2,}',
        r'[?]{2,}',
        
        # All caps words (potential shouting/urgency)
        r'\b[A-Z]{4,}\b',
        
        # Repeated characters (urgency/emphasis)
        r'(.)\1{3,}',
        
        # Phone number patterns
        r'\b(?:\+91|91)?[6-9]\d{9}\b',
        
        # UPI ID patterns
        r'\b\w+@(?:paytm|phonepe|googlepay|okaxis|ybl|ibl|axl)\b',
        
        # URL patterns (potentially malicious)
        r'https?://[^\s]+',
        
        # Email patterns
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    ]
    
    def __init__(self):
        """Initialize the scam detection engine."""
        self.compiled_patterns = {
            'contact_requests': [re.compile(pattern, re.IGNORECASE) for pattern in self.CONTACT_REQUEST_PATTERNS],
            'suspicious': [re.compile(pattern, re.IGNORECASE) for pattern in self.SUSPICIOUS_PATTERNS]
        }
        
        # Initialize ML detector
        self.ml_detector = MLScamDetector()
        
        # Train ML detector with synthetic data if not already trained
        if not self.ml_detector.is_trained:
            try:
                logger.info("Training ML detector with synthetic data")
                training_results = self.ml_detector.train_with_synthetic_data()
                logger.info(f"ML detector trained. Test accuracy: {training_results['test_metrics']['accuracy']:.3f}")
            except Exception as e:
                logger.warning(f"Failed to train ML detector: {e}")
                logger.info("Continuing with rule-based detection only")
    
    def calculate_risk_score(
        self,
        message: str,
        conversation_history: List[Dict[str, Any]] = None,
        metadata: Dict[str, Any] = None
    ) -> Tuple[float, float]:
        """
        Calculate risk score for a message.
        
        Args:
            message: Message content to analyze
            conversation_history: Previous conversation messages
            metadata: Additional metadata about the message
            
        Returns:
            Tuple[float, float]: (risk_score, confidence)
        """
        if conversation_history is None:
            conversation_history = []
        if metadata is None:
            metadata = {}
        
        # Start timing for performance tracking
        start_time = time.time()
        
        try:
            # Perform comprehensive risk assessment
            assessment = self.analyze_message(message, conversation_history, metadata)
            
            # Calculate processing time
            processing_time_ms = int((time.time() - start_time) * 1000)
            
            # Prepare audit logging data
            session_id = metadata.get('session_id', 'unknown')
            message_id = metadata.get('message_id')
            correlation_id = metadata.get('correlation_id')
            
            # Extract conversation context for audit
            conversation_context = {
                'turn': len(conversation_history) + 1,
                'message_length': len(message),
                'language': metadata.get('language', 'en'),
                'has_history': len(conversation_history) > 0
            }
            
            # Prepare contributing factors for audit
            contributing_factors = {
                'analysis_components': {
                    'rule_based': assessment.details.get('rule_based_score', 0.0),
                    'keyword_analysis': assessment.details.get('keyword_score', 0.0),
                    'pattern_matching': assessment.details.get('pattern_score', 0.0),
                    'contextual_analysis': assessment.details.get('context_score', 0.0),
                    'ml_classification': assessment.details.get('ml_score', 0.0)
                },
                'risk_factor_categories': self._categorize_risk_factors(assessment.risk_factors),
                'confidence_factors': {
                    'ml_agreement': assessment.ml_prediction is not None,
                    'multiple_indicators': len(set(self._extract_risk_categories(assessment.risk_factors))) > 1,
                    'contextual_support': assessment.details.get('context_score', 0.0) > 0.1
                },
                'temporal_analysis': assessment.details.get('contextual_analysis', {}).get('temporal_patterns_detected', False),
                'conversation_flow': assessment.details.get('contextual_analysis', {}).get('conversation_flow_analyzed', False),
                'cross_session_patterns': assessment.details.get('contextual_analysis', {}).get('cross_session_patterns', False)
            }
            
            # Log comprehensive audit event
            audit_event_id = audit_logger.log_risk_assessment(
                session_id=session_id,
                message_id=message_id,
                risk_score=assessment.risk_score,
                confidence=assessment.confidence,
                detection_method=assessment.detection_method.value,
                risk_factors=assessment.risk_factors,
                contributing_factors=contributing_factors,
                analysis_breakdown=assessment.details,
                conversation_context=conversation_context,
                ml_prediction=assessment.ml_prediction,
                temporal_patterns=assessment.details.get('temporal_patterns'),
                cross_session_patterns=assessment.details.get('cross_session_patterns'),
                processing_time_ms=processing_time_ms,
                correlation_id=correlation_id
            )
            
            # Log basic info for backwards compatibility
            logger.info(
                "Risk assessment completed",
                extra={
                    "audit_event_id": audit_event_id,
                    "session_id": session_id,
                    "risk_score": assessment.risk_score,
                    "confidence": assessment.confidence,
                    "method": assessment.detection_method.value,
                    "risk_factors": assessment.risk_factors,
                    "processing_time_ms": processing_time_ms
                }
            )
            
            return assessment.risk_score, assessment.confidence
            
        except Exception as e:
            # Calculate processing time even for errors
            processing_time_ms = int((time.time() - start_time) * 1000)
            
            # Log error audit event
            error_details = {
                "error_type": type(e).__name__,
                "error_message": str(e),
                "message_length": len(message),
                "conversation_history_length": len(conversation_history),
                "metadata_keys": list(metadata.keys()) if metadata else [],
                "processing_time_ms": processing_time_ms
            }
            
            audit_logger.log_system_error(
                error_type="risk_assessment_error",
                error_message=f"Error calculating risk score: {e}",
                error_details=error_details,
                session_id=metadata.get('session_id'),
                correlation_id=metadata.get('correlation_id')
            )
            
            logger.error(f"Error calculating risk score: {e}", exc_info=True)
            # Return low risk score with low confidence on error
            return 0.1, 0.3
    
    def analyze_message(
        self,
        message: str,
        conversation_history: List[Dict[str, Any]],
        metadata: Dict[str, Any]
    ) -> RiskAssessment:
        """
        Perform comprehensive message analysis.
        
        Args:
            message: Message content to analyze
            conversation_history: Previous conversation messages
            metadata: Additional metadata
            
        Returns:
            RiskAssessment: Detailed risk assessment
        """
        risk_factors = []
        risk_scores = []
        details = {}
        ml_prediction = None
        
        # Rule-based analysis
        rule_score, rule_factors = self._analyze_rule_based(message)
        risk_scores.append(rule_score)
        risk_factors.extend(rule_factors)
        details['rule_based_score'] = rule_score
        
        # Keyword analysis
        keyword_score, keyword_factors = self._analyze_keywords(message)
        risk_scores.append(keyword_score)
        risk_factors.extend(keyword_factors)
        details['keyword_score'] = keyword_score
        
        # Pattern matching
        pattern_score, pattern_factors = self._analyze_patterns(message)
        risk_scores.append(pattern_score)
        risk_factors.extend(pattern_factors)
        details['pattern_score'] = pattern_score
        
        # Contextual analysis (if conversation history available)
        context_score, context_factors = self._analyze_context(message, conversation_history)
        risk_scores.append(context_score)
        risk_factors.extend(context_factors)
        details['context_score'] = context_score
        details['contextual_analysis'] = {
            'temporal_patterns_detected': any('frequency' in factor or 'timing' in factor or 'velocity' in factor for factor in context_factors),
            'conversation_flow_analyzed': any('topic' in factor or 'pressure' in factor or 'stage' in factor for factor in context_factors),
            'cross_session_patterns': any('session' in factor or 'pattern' in factor or 'entity' in factor for factor in context_factors),
            'engagement_tactics_detected': [factor for factor in context_factors if 'tactic' in factor]
        }
        
        # ML-based classification
        ml_score, ml_factors = self._analyze_ml_classification(message, conversation_history)
        risk_scores.append(ml_score)
        risk_factors.extend(ml_factors)
        details['ml_score'] = ml_score
        
        # Get ML prediction details
        if self.ml_detector.is_trained:
            try:
                conversation_texts = [msg.get('content', '') for msg in conversation_history]
                ml_pred = self.ml_detector.predict(message, conversation_texts)
                ml_prediction = {
                    'probability': ml_pred.probability,
                    'confidence': ml_pred.confidence,
                    'model_predictions': ml_pred.model_predictions,
                    'top_features': dict(list(ml_pred.feature_importance.items())[:5])  # Top 5 features
                }
            except Exception as e:
                logger.warning(f"ML prediction failed: {e}")
        
        # Calculate weighted final score
        final_score = self._calculate_weighted_score(risk_scores)
        
        # Apply risk factor multiplier for multiple different types of indicators
        unique_risk_types = set()
        for factor in risk_factors:
            if 'financial' in factor or 'money' in factor:
                unique_risk_types.add('financial')
            elif 'urgency' in factor or 'urgent' in factor:
                unique_risk_types.add('urgency')
            elif 'social' in factor or 'authority' in factor or 'trust' in factor:
                unique_risk_types.add('social_engineering')
            elif 'contact' in factor or 'info' in factor:
                unique_risk_types.add('information_gathering')
            elif 'phone' in factor or 'upi' in factor or 'url' in factor:
                unique_risk_types.add('suspicious_patterns')
            elif 'ml_' in factor:
                unique_risk_types.add('ml_indicators')
        
        # Boost score based on diversity of risk factors
        if len(unique_risk_types) >= 4:
            # Multiple different types of scam indicators including ML
            final_score *= 1.5
        elif len(unique_risk_types) >= 3:
            # Multiple different types of indicators
            final_score *= 1.4
        elif len(unique_risk_types) >= 2:
            # Two different types of indicators
            final_score *= 1.2
        
        # Calculate confidence based on consistency of scores
        confidence = self._calculate_confidence(risk_scores, risk_factors)
        
        # Boost confidence if ML and rule-based agree
        if ml_prediction and len(risk_scores) >= 2:
            ml_prob = ml_prediction['probability']
            rule_based_avg = sum(risk_scores[:-1]) / len(risk_scores[:-1])  # Exclude ML score
            
            # If both ML and rule-based indicate high risk, boost confidence
            if ml_prob > 0.7 and rule_based_avg > 0.5:
                confidence *= 1.3
            elif ml_prob > 0.5 and rule_based_avg > 0.3:
                confidence *= 1.1
        
        # Ensure scores are within valid range
        final_score = max(0.0, min(1.0, final_score))
        confidence = max(0.0, min(1.0, confidence))
        
        return RiskAssessment(
            risk_score=final_score,
            confidence=confidence,
            detection_method=DetectionMethod.COMBINED,
            risk_factors=list(set(risk_factors)),  # Remove duplicates
            details=details,
            ml_prediction=ml_prediction
        )
    
    def _analyze_rule_based(self, message: str) -> Tuple[float, List[str]]:
        """
        Analyze message using rule-based filters.
        
        Args:
            message: Message to analyze
            
        Returns:
            Tuple[float, List[str]]: (score, risk_factors)
        """
        risk_factors = []
        score = 0.0
        
        message_lower = message.lower()
        
        # Check for financial keywords - increased scoring
        financial_matches = sum(1 for keyword in self.FINANCIAL_KEYWORDS if keyword in message_lower)
        if financial_matches > 0:
            risk_factors.append(f"financial_keywords_{financial_matches}")
            # More aggressive scoring for financial keywords
            score += min(0.4, financial_matches * 0.15)
        
        # Check for urgency indicators - increased scoring
        urgency_matches = sum(1 for keyword in self.URGENCY_KEYWORDS if keyword in message_lower)
        if urgency_matches > 0:
            risk_factors.append(f"urgency_indicators_{urgency_matches}")
            # More aggressive scoring for urgency
            score += min(0.3, urgency_matches * 0.1)
        
        # Check for social engineering - increased scoring
        social_matches = sum(1 for keyword in self.SOCIAL_ENGINEERING_KEYWORDS if keyword in message_lower)
        if social_matches > 0:
            risk_factors.append(f"social_engineering_{social_matches}")
            # More aggressive scoring for social engineering
            score += min(0.35, social_matches * 0.1)
        
        return min(score, 0.6), risk_factors
    
    def _analyze_keywords(self, message: str) -> Tuple[float, List[str]]:
        """
        Analyze message for specific keyword patterns.
        
        Args:
            message: Message to analyze
            
        Returns:
            Tuple[float, List[str]]: (score, risk_factors)
        """
        risk_factors = []
        score = 0.0
        
        # Check for contact information requests - increased scoring
        for pattern in self.compiled_patterns['contact_requests']:
            if pattern.search(message):
                risk_factors.append("contact_info_request")
                score += 0.25  # Increased from 0.15
                break
        
        # Check for money-related urgency combinations - increased scoring
        if any(keyword in message.lower() for keyword in ['money', 'payment', 'transfer']) and \
           any(keyword in message.lower() for keyword in ['urgent', 'immediately', 'asap']):
            risk_factors.append("urgent_money_request")
            score += 0.3  # Increased from 0.2
        
        # Check for trust-building with financial requests - increased scoring
        if any(keyword in message.lower() for keyword in ['trust', 'honest', 'genuine']) and \
           any(keyword in message.lower() for keyword in self.FINANCIAL_KEYWORDS):
            risk_factors.append("trust_building_financial")
            score += 0.25  # Increased from 0.15
        
        # Check for authority claims with financial requests
        authority_keywords = ['officer', 'manager', 'executive', 'representative', 'agent', 'official']
        if any(keyword in message.lower() for keyword in authority_keywords) and \
           any(keyword in message.lower() for keyword in self.FINANCIAL_KEYWORDS):
            risk_factors.append("authority_financial_request")
            score += 0.3
        
        # Check for fear tactics with urgency
        fear_keywords = ['blocked', 'suspended', 'cancelled', 'expired', 'penalty', 'fine']
        if any(keyword in message.lower() for keyword in fear_keywords) and \
           any(keyword in message.lower() for keyword in self.URGENCY_KEYWORDS):
            risk_factors.append("fear_urgency_combination")
            score += 0.25
        
        return min(score, 0.5), risk_factors
    
    def _analyze_patterns(self, message: str) -> Tuple[float, List[str]]:
        """
        Analyze message for suspicious patterns.
        
        Args:
            message: Message to analyze
            
        Returns:
            Tuple[float, List[str]]: (score, risk_factors)
        """
        risk_factors = []
        score = 0.0
        
        # Check suspicious patterns with improved scoring
        for pattern in self.compiled_patterns['suspicious']:
            matches = pattern.findall(message)
            if matches:
                if 'phone' in pattern.pattern or r'\b(?:\+91|91)?[6-9]\d{9}\b' in pattern.pattern:
                    risk_factors.append("phone_number_detected")
                    score += 0.2  # Increased from 0.1
                elif 'upi' in pattern.pattern or '@(?:paytm|phonepe|googlepay|okaxis|ybl|ibl|axl)' in pattern.pattern:
                    risk_factors.append("upi_id_detected")
                    score += 0.25  # Increased from 0.15
                elif 'http' in pattern.pattern:
                    risk_factors.append("url_detected")
                    score += 0.15  # Increased from 0.1
                elif '[!]' in pattern.pattern or '[?]' in pattern.pattern:
                    risk_factors.append("excessive_punctuation")
                    score += 0.1  # Increased from 0.05
                elif '[A-Z]' in pattern.pattern:
                    risk_factors.append("excessive_caps")
                    score += 0.1  # Increased from 0.05
                elif r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}' in pattern.pattern:
                    risk_factors.append("email_detected")
                    score += 0.15
        
        # Additional pattern checks
        # Check for multiple exclamation marks (strong urgency indicator)
        if len(re.findall(r'!{3,}', message)) > 0:
            risk_factors.append("excessive_exclamation")
            score += 0.15
        
        # Check for all caps words (shouting/urgency)
        caps_words = re.findall(r'\b[A-Z]{4,}\b', message)
        if len(caps_words) > 0:
            risk_factors.append("shouting_detected")
            score += min(0.2, len(caps_words) * 0.05)
        
        return min(score, 0.4), risk_factors
    
    def _analyze_context(
        self,
        message: str,
        conversation_history: List[Dict[str, Any]]
    ) -> Tuple[float, List[str]]:
        """
        Enhanced analyze message in context of conversation history with temporal analysis.
        
        Args:
            message: Current message
            conversation_history: Previous messages
            
        Returns:
            Tuple[float, List[str]]: (score, risk_factors)
        """
        risk_factors = []
        score = 0.0
        
        if not conversation_history:
            return score, risk_factors
        
        # Perform temporal analysis
        temporal_pattern = self._analyze_temporal_patterns(conversation_history)
        temporal_score, temporal_factors = self._score_temporal_patterns(temporal_pattern)
        score += temporal_score
        risk_factors.extend(temporal_factors)
        
        # Perform conversation flow analysis
        conversation_flow = self._analyze_conversation_flow(message, conversation_history)
        flow_score, flow_factors = self._score_conversation_flow(conversation_flow)
        score += flow_score
        risk_factors.extend(flow_factors)
        
        # Perform cross-session pattern recognition
        cross_session_pattern = self._analyze_cross_session_patterns(conversation_history)
        cross_score, cross_factors = self._score_cross_session_patterns(cross_session_pattern)
        score += cross_score
        risk_factors.extend(cross_factors)
        
        # Legacy pattern analysis (enhanced)
        legacy_score, legacy_factors = self._analyze_legacy_patterns(conversation_history)
        score += legacy_score
        risk_factors.extend(legacy_factors)
        
        return min(score, 0.4), risk_factors
    
    def _analyze_temporal_patterns(self, conversation_history: List[Dict[str, Any]]) -> TemporalPattern:
        """
        Analyze temporal patterns in conversation history.
        
        Args:
            conversation_history: Previous messages with timestamps
            
        Returns:
            TemporalPattern: Temporal analysis result
        """
        if len(conversation_history) < 2:
            return TemporalPattern(
                message_frequency=0.0,
                avg_response_time=0.0,
                urgency_escalation=False,
                conversation_velocity=0.0,
                timing_anomalies=[]
            )
        
        # Extract timestamps and calculate timing metrics
        timestamps = []
        urgency_scores = []
        timing_anomalies = []
        
        for msg in conversation_history:
            # Parse timestamp (handle both string and datetime objects)
            timestamp = msg.get('timestamp')
            if isinstance(timestamp, str):
                try:
                    timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                except (ValueError, AttributeError):
                    # Fallback to current time if parsing fails
                    timestamp = datetime.utcnow()
            elif not isinstance(timestamp, datetime):
                timestamp = datetime.utcnow()
            
            timestamps.append(timestamp)
            
            # Calculate urgency score for this message
            content = msg.get('content', '').lower()
            urgency_score = sum(1 for keyword in self.URGENCY_KEYWORDS if keyword in content)
            urgency_scores.append(urgency_score)
        
        # Calculate message frequency (messages per minute)
        if len(timestamps) >= 2:
            time_span = (timestamps[-1] - timestamps[0]).total_seconds() / 60.0  # minutes
            message_frequency = len(timestamps) / max(time_span, 0.1)  # Avoid division by zero
        else:
            message_frequency = 0.0
        
        # Calculate average response time between consecutive messages
        response_times = []
        for i in range(1, len(timestamps)):
            time_diff = (timestamps[i] - timestamps[i-1]).total_seconds()
            response_times.append(time_diff)
            
            # Detect timing anomalies
            if time_diff < 5:  # Very fast response (< 5 seconds)
                timing_anomalies.append("very_fast_response")
            elif time_diff > 300:  # Very slow response (> 5 minutes)
                timing_anomalies.append("very_slow_response")
        
        avg_response_time = statistics.mean(response_times) if response_times else 0.0
        
        # Detect urgency escalation
        urgency_escalation = False
        if len(urgency_scores) >= 3:
            # Check if urgency is increasing over time
            recent_urgency = statistics.mean(urgency_scores[-3:])
            early_urgency = statistics.mean(urgency_scores[:3])
            urgency_escalation = recent_urgency > early_urgency
        
        # Calculate conversation velocity (topic changes per message)
        conversation_velocity = self._calculate_conversation_velocity(conversation_history)
        
        # Detect rapid-fire messaging pattern
        if len(response_times) >= 3:
            recent_responses = response_times[-3:]
            if all(rt < 30 for rt in recent_responses):  # All responses < 30 seconds
                timing_anomalies.append("rapid_fire_messaging")
        
        # Detect unusual timing patterns
        if response_times:
            response_variance = statistics.variance(response_times) if len(response_times) > 1 else 0
            if response_variance > 10000:  # High variance in response times
                timing_anomalies.append("erratic_timing_pattern")
        
        return TemporalPattern(
            message_frequency=message_frequency,
            avg_response_time=avg_response_time,
            urgency_escalation=urgency_escalation,
            conversation_velocity=conversation_velocity,
            timing_anomalies=list(set(timing_anomalies))  # Remove duplicates
        )
    
    def _calculate_conversation_velocity(self, conversation_history: List[Dict[str, Any]]) -> float:
        """
        Calculate how quickly the conversation is progressing through topics.
        
        Args:
            conversation_history: Previous messages
            
        Returns:
            float: Conversation velocity score
        """
        if len(conversation_history) < 2:
            return 0.0
        
        # Count topic indicators
        financial_mentions = 0
        contact_requests = 0
        urgency_mentions = 0
        authority_claims = 0
        
        for msg in conversation_history:
            content = msg.get('content', '').lower()
            
            if any(keyword in content for keyword in self.FINANCIAL_KEYWORDS):
                financial_mentions += 1
            
            if any(keyword in content for keyword in self.URGENCY_KEYWORDS):
                urgency_mentions += 1
            
            # Check for contact requests
            for pattern in self.compiled_patterns['contact_requests']:
                if pattern.search(content):
                    contact_requests += 1
                    break
            
            # Check for authority claims
            authority_keywords = ['officer', 'manager', 'executive', 'representative', 'agent', 'official']
            if any(keyword in content for keyword in authority_keywords):
                authority_claims += 1
        
        # Calculate velocity as topics per message
        total_topics = financial_mentions + contact_requests + urgency_mentions + authority_claims
        velocity = total_topics / len(conversation_history)
        
        return min(velocity, 2.0)  # Cap at 2.0
    
    def _score_temporal_patterns(self, temporal_pattern: TemporalPattern) -> Tuple[float, List[str]]:
        """
        Score temporal patterns for risk assessment.
        
        Args:
            temporal_pattern: Temporal analysis result
            
        Returns:
            Tuple[float, List[str]]: (score, risk_factors)
        """
        score = 0.0
        risk_factors = []
        
        # High message frequency indicates urgency/pressure
        if temporal_pattern.message_frequency > 5.0:  # > 5 messages per minute
            risk_factors.append("high_message_frequency")
            score += 0.15
        elif temporal_pattern.message_frequency > 2.0:  # > 2 messages per minute
            risk_factors.append("elevated_message_frequency")
            score += 0.08
        
        # Very fast responses can indicate automated/scripted behavior
        if temporal_pattern.avg_response_time < 10:  # < 10 seconds average
            risk_factors.append("very_fast_responses")
            score += 0.12
        elif temporal_pattern.avg_response_time < 30:  # < 30 seconds average
            risk_factors.append("fast_responses")
            score += 0.06
        
        # Urgency escalation is a strong scam indicator
        if temporal_pattern.urgency_escalation:
            risk_factors.append("urgency_escalation_detected")
            score += 0.20
        
        # High conversation velocity indicates rushing
        if temporal_pattern.conversation_velocity > 1.5:
            risk_factors.append("high_conversation_velocity")
            score += 0.15
        elif temporal_pattern.conversation_velocity > 1.0:
            risk_factors.append("elevated_conversation_velocity")
            score += 0.08
        
        # Score timing anomalies
        for anomaly in temporal_pattern.timing_anomalies:
            if anomaly == "rapid_fire_messaging":
                risk_factors.append("rapid_fire_messaging_pattern")
                score += 0.18
            elif anomaly == "very_fast_response":
                risk_factors.append("suspiciously_fast_responses")
                score += 0.10
            elif anomaly == "erratic_timing_pattern":
                risk_factors.append("erratic_response_timing")
                score += 0.08
        
        return min(score, 0.25), risk_factors
    
    def _analyze_conversation_flow(
        self, 
        current_message: str, 
        conversation_history: List[Dict[str, Any]]
    ) -> ConversationFlow:
        """
        Analyze conversation flow and progression patterns.
        
        Args:
            current_message: Current message being analyzed
            conversation_history: Previous messages
            
        Returns:
            ConversationFlow: Conversation flow analysis
        """
        # Count topic shifts
        topic_shifts = self._count_topic_shifts(conversation_history + [{'content': current_message}])
        
        # Count information requests
        information_requests = 0
        for msg in conversation_history + [{'content': current_message}]:
            content = msg.get('content', '')
            for pattern in self.compiled_patterns['contact_requests']:
                if pattern.search(content):
                    information_requests += 1
                    break
        
        # Calculate pressure escalation
        pressure_escalation = self._calculate_pressure_escalation(conversation_history)
        
        # Detect engagement tactics
        engagement_tactics = self._detect_engagement_tactics(conversation_history)
        
        # Determine conversation stage
        conversation_stage = self._determine_conversation_stage(conversation_history, current_message)
        
        return ConversationFlow(
            topic_shifts=topic_shifts,
            information_requests=information_requests,
            pressure_escalation=pressure_escalation,
            engagement_tactics=engagement_tactics,
            conversation_stage=conversation_stage
        )
    
    def _count_topic_shifts(self, messages: List[Dict[str, Any]]) -> int:
        """Count the number of topic shifts in the conversation."""
        if len(messages) < 2:
            return 0
        
        topics = []
        for msg in messages:
            content = msg.get('content', '').lower()
            current_topics = set()
            
            if any(keyword in content for keyword in self.FINANCIAL_KEYWORDS):
                current_topics.add('financial')
            if any(keyword in content for keyword in self.URGENCY_KEYWORDS):
                current_topics.add('urgency')
            if any(keyword in content for keyword in ['trust', 'honest', 'genuine']):
                current_topics.add('trust_building')
            if any(keyword in content for keyword in ['officer', 'manager', 'official']):
                current_topics.add('authority')
            
            # Check for contact requests
            for pattern in self.compiled_patterns['contact_requests']:
                if pattern.search(content):
                    current_topics.add('contact_request')
                    break
            
            topics.append(current_topics)
        
        # Count transitions between different topic sets
        shifts = 0
        for i in range(1, len(topics)):
            if topics[i] != topics[i-1] and topics[i]:  # Topic changed and not empty
                shifts += 1
        
        return shifts
    
    def _calculate_pressure_escalation(self, conversation_history: List[Dict[str, Any]]) -> float:
        """Calculate pressure escalation score."""
        if len(conversation_history) < 2:
            return 0.0
        
        # Analyze pressure indicators over time
        pressure_scores = []
        for msg in conversation_history:
            content = msg.get('content', '').lower()
            pressure_score = 0.0
            
            # Urgency indicators
            urgency_count = sum(1 for keyword in self.URGENCY_KEYWORDS if keyword in content)
            pressure_score += urgency_count * 0.3
            
            # Financial pressure
            financial_count = sum(1 for keyword in self.FINANCIAL_KEYWORDS if keyword in content)
            pressure_score += financial_count * 0.2
            
            # Authority claims
            authority_keywords = ['officer', 'manager', 'official', 'representative']
            authority_count = sum(1 for keyword in authority_keywords if keyword in content)
            pressure_score += authority_count * 0.25
            
            # Fear tactics
            fear_keywords = ['blocked', 'suspended', 'penalty', 'fine', 'legal action']
            fear_count = sum(1 for keyword in fear_keywords if keyword in content)
            pressure_score += fear_count * 0.4
            
            pressure_scores.append(pressure_score)
        
        # Calculate escalation (recent vs early pressure)
        if len(pressure_scores) >= 4:
            recent_pressure = statistics.mean(pressure_scores[-2:])
            early_pressure = statistics.mean(pressure_scores[:2])
            escalation = max(0.0, recent_pressure - early_pressure)
        else:
            escalation = max(pressure_scores) if pressure_scores else 0.0
        
        return min(escalation, 1.0)
    
    def _detect_engagement_tactics(self, conversation_history: List[Dict[str, Any]]) -> List[str]:
        """Detect engagement tactics used in the conversation."""
        tactics = []
        
        # Analyze all messages for tactics
        trust_building_count = 0
        authority_claims_count = 0
        urgency_creation_count = 0
        fear_induction_count = 0
        social_proof_count = 0
        
        for msg in conversation_history:
            content = msg.get('content', '').lower()
            
            # Trust building
            trust_keywords = ['trust', 'honest', 'genuine', 'believe', 'legitimate']
            if any(keyword in content for keyword in trust_keywords):
                trust_building_count += 1
            
            # Authority claims
            authority_keywords = ['officer', 'manager', 'official', 'representative', 'authorized']
            if any(keyword in content for keyword in authority_keywords):
                authority_claims_count += 1
            
            # Urgency creation
            if any(keyword in content for keyword in self.URGENCY_KEYWORDS):
                urgency_creation_count += 1
            
            # Fear induction
            fear_keywords = ['blocked', 'suspended', 'penalty', 'fine', 'legal', 'police']
            if any(keyword in content for keyword in fear_keywords):
                fear_induction_count += 1
            
            # Social proof
            social_keywords = ['others', 'everyone', 'many people', 'customers', 'users']
            if any(keyword in content for keyword in social_keywords):
                social_proof_count += 1
        
        # Determine which tactics are being used
        if trust_building_count >= 2:
            tactics.append('trust_building')
        if authority_claims_count >= 1:
            tactics.append('authority_impersonation')
        if urgency_creation_count >= 2:
            tactics.append('urgency_creation')
        if fear_induction_count >= 1:
            tactics.append('fear_induction')
        if social_proof_count >= 1:
            tactics.append('social_proof')
        
        return tactics
    
    def _determine_conversation_stage(
        self, 
        conversation_history: List[Dict[str, Any]], 
        current_message: str
    ) -> str:
        """Determine the current stage of the conversation."""
        total_messages = len(conversation_history) + 1
        
        # Analyze content progression
        has_financial_request = False
        has_contact_request = False
        has_urgency = False
        has_authority_claim = False
        
        all_messages = conversation_history + [{'content': current_message}]
        
        for msg in all_messages:
            content = msg.get('content', '').lower()
            
            if any(keyword in content for keyword in self.FINANCIAL_KEYWORDS):
                has_financial_request = True
            
            if any(keyword in content for keyword in self.URGENCY_KEYWORDS):
                has_urgency = True
            
            authority_keywords = ['officer', 'manager', 'official', 'representative']
            if any(keyword in content for keyword in authority_keywords):
                has_authority_claim = True
            
            # Check for contact requests
            for pattern in self.compiled_patterns['contact_requests']:
                if pattern.search(content):
                    has_contact_request = True
                    break
        
        # Determine stage based on content and message count
        if total_messages <= 2:
            return 'initial_contact'
        elif total_messages <= 4:
            if has_authority_claim:
                return 'credibility_establishment'
            else:
                return 'rapport_building'
        elif total_messages <= 7:
            if has_financial_request or has_contact_request:
                return 'information_gathering'
            else:
                return 'trust_building'
        else:
            if has_urgency and (has_financial_request or has_contact_request):
                return 'pressure_application'
            else:
                return 'extended_engagement'
    
    def _score_conversation_flow(self, conversation_flow: ConversationFlow) -> Tuple[float, List[str]]:
        """Score conversation flow patterns for risk assessment."""
        score = 0.0
        risk_factors = []
        
        # Multiple topic shifts indicate manipulation
        if conversation_flow.topic_shifts >= 4:
            risk_factors.append("excessive_topic_shifting")
            score += 0.15
        elif conversation_flow.topic_shifts >= 2:
            risk_factors.append("multiple_topic_shifts")
            score += 0.08
        
        # Multiple information requests are suspicious
        if conversation_flow.information_requests >= 3:
            risk_factors.append("excessive_information_requests")
            score += 0.20
        elif conversation_flow.information_requests >= 2:
            risk_factors.append("multiple_information_requests")
            score += 0.12
        elif conversation_flow.information_requests >= 1:
            risk_factors.append("information_request_detected")
            score += 0.06
        
        # High pressure escalation is a strong indicator
        if conversation_flow.pressure_escalation > 0.7:
            risk_factors.append("high_pressure_escalation")
            score += 0.25
        elif conversation_flow.pressure_escalation > 0.4:
            risk_factors.append("moderate_pressure_escalation")
            score += 0.15
        elif conversation_flow.pressure_escalation > 0.2:
            risk_factors.append("low_pressure_escalation")
            score += 0.08
        
        # Score engagement tactics
        for tactic in conversation_flow.engagement_tactics:
            if tactic == 'fear_induction':
                risk_factors.append("fear_induction_tactic")
                score += 0.20
            elif tactic == 'authority_impersonation':
                risk_factors.append("authority_impersonation_tactic")
                score += 0.18
            elif tactic == 'urgency_creation':
                risk_factors.append("urgency_creation_tactic")
                score += 0.15
            elif tactic == 'trust_building':
                risk_factors.append("trust_building_tactic")
                score += 0.10
            elif tactic == 'social_proof':
                risk_factors.append("social_proof_tactic")
                score += 0.08
        
        # Score conversation stage progression
        if conversation_flow.conversation_stage == 'pressure_application':
            risk_factors.append("pressure_application_stage")
            score += 0.20
        elif conversation_flow.conversation_stage == 'information_gathering':
            risk_factors.append("information_gathering_stage")
            score += 0.15
        
        return min(score, 0.30), risk_factors
    
    def _analyze_cross_session_patterns(self, conversation_history: List[Dict[str, Any]]) -> CrossSessionPattern:
        """
        Analyze patterns across sessions for repeat detection.
        
        Note: This is a simplified implementation. In a production system,
        this would query the database for similar sessions.
        
        Args:
            conversation_history: Current conversation history
            
        Returns:
            CrossSessionPattern: Cross-session analysis result
        """
        # For now, implement basic pattern matching
        # In production, this would involve database queries
        
        similar_sessions = 0
        repeat_indicators = []
        entity_overlap = 0
        pattern_confidence = 0.0
        
        # Extract entities from current conversation
        current_entities = self._extract_conversation_entities(conversation_history)
        
        # Analyze conversation patterns
        conversation_signature = self._generate_conversation_signature(conversation_history)
        
        # Check for common scam patterns (simplified)
        if self._has_common_scam_signature(conversation_signature):
            repeat_indicators.append("common_scam_pattern")
            similar_sessions += 1
            pattern_confidence += 0.3
        
        # Check for entity patterns
        if current_entities:
            entity_overlap = len(current_entities)
            if entity_overlap >= 2:
                repeat_indicators.append("multiple_entities_detected")
                pattern_confidence += 0.2
        
        # Check for timing patterns (simplified)
        if self._has_suspicious_timing_pattern(conversation_history):
            repeat_indicators.append("suspicious_timing_pattern")
            pattern_confidence += 0.1
        
        return CrossSessionPattern(
            similar_sessions=similar_sessions,
            repeat_indicators=repeat_indicators,
            entity_overlap=entity_overlap,
            pattern_confidence=min(pattern_confidence, 1.0)
        )
    
    def _extract_conversation_entities(self, conversation_history: List[Dict[str, Any]]) -> List[str]:
        """Extract entities from conversation history."""
        entities = []
        
        for msg in conversation_history:
            content = msg.get('content', '')
            
            # Extract phone numbers
            phone_matches = re.findall(r'\b(?:\+91|91)?[6-9]\d{9}\b', content)
            entities.extend(phone_matches)
            
            # Extract UPI IDs
            upi_matches = re.findall(r'\b\w+@(?:paytm|phonepe|googlepay|okaxis|ybl|ibl|axl)\b', content)
            entities.extend(upi_matches)
            
            # Extract URLs
            url_matches = re.findall(r'https?://[^\s]+', content)
            entities.extend(url_matches)
            
            # Extract email addresses
            email_matches = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', content)
            entities.extend(email_matches)
        
        return list(set(entities))  # Remove duplicates
    
    def _generate_conversation_signature(self, conversation_history: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate a signature for the conversation pattern."""
        signature = {
            'financial_keywords': 0,
            'urgency_keywords': 0,
            'authority_claims': 0,
            'contact_requests': 0,
            'trust_building': 0,
            'message_count': len(conversation_history)
        }
        
        for msg in conversation_history:
            content = msg.get('content', '').lower()
            
            # Count keyword categories
            signature['financial_keywords'] += sum(1 for kw in self.FINANCIAL_KEYWORDS if kw in content)
            signature['urgency_keywords'] += sum(1 for kw in self.URGENCY_KEYWORDS if kw in content)
            
            authority_keywords = ['officer', 'manager', 'official', 'representative']
            signature['authority_claims'] += sum(1 for kw in authority_keywords if kw in content)
            
            trust_keywords = ['trust', 'honest', 'genuine', 'believe']
            signature['trust_building'] += sum(1 for kw in trust_keywords if kw in content)
            
            # Check for contact requests
            for pattern in self.compiled_patterns['contact_requests']:
                if pattern.search(content):
                    signature['contact_requests'] += 1
                    break
        
        return signature
    
    def _has_common_scam_signature(self, signature: Dict[str, Any]) -> bool:
        """Check if conversation signature matches common scam patterns."""
        # Define common scam patterns
        if (signature['financial_keywords'] >= 2 and 
            signature['urgency_keywords'] >= 1 and 
            signature['contact_requests'] >= 1):
            return True
        
        if (signature['authority_claims'] >= 1 and 
            signature['financial_keywords'] >= 1 and 
            signature['urgency_keywords'] >= 1):
            return True
        
        if (signature['trust_building'] >= 2 and 
            signature['financial_keywords'] >= 1):
            return True
        
        return False
    
    def _has_suspicious_timing_pattern(self, conversation_history: List[Dict[str, Any]]) -> bool:
        """Check for suspicious timing patterns."""
        if len(conversation_history) < 3:
            return False
        
        # Check for very rapid responses (potential bot behavior)
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
                if time_diff < 5:  # Less than 5 seconds
                    rapid_responses += 1
        
        return rapid_responses >= 2
    
    def _score_cross_session_patterns(self, cross_session_pattern: CrossSessionPattern) -> Tuple[float, List[str]]:
        """Score cross-session patterns for risk assessment."""
        score = 0.0
        risk_factors = []
        
        # Similar sessions indicate repeat behavior
        if cross_session_pattern.similar_sessions >= 3:
            risk_factors.append("multiple_similar_sessions")
            score += 0.25
        elif cross_session_pattern.similar_sessions >= 1:
            risk_factors.append("similar_session_detected")
            score += 0.15
        
        # Score repeat indicators
        for indicator in cross_session_pattern.repeat_indicators:
            if indicator == "common_scam_pattern":
                risk_factors.append("matches_common_scam_pattern")
                score += 0.20
            elif indicator == "multiple_entities_detected":
                risk_factors.append("multiple_entities_in_conversation")
                score += 0.15
            elif indicator == "suspicious_timing_pattern":
                risk_factors.append("suspicious_timing_detected")
                score += 0.10
        
        # Entity overlap scoring
        if cross_session_pattern.entity_overlap >= 3:
            risk_factors.append("high_entity_overlap")
            score += 0.18
        elif cross_session_pattern.entity_overlap >= 2:
            risk_factors.append("moderate_entity_overlap")
            score += 0.12
        
        # Pattern confidence boost
        if cross_session_pattern.pattern_confidence > 0.7:
            score *= 1.2  # Boost score for high confidence patterns
        
        return min(score, 0.25), risk_factors
    
    def _analyze_legacy_patterns(self, conversation_history: List[Dict[str, Any]]) -> Tuple[float, List[str]]:
        """
        Analyze legacy patterns (enhanced version of original context analysis).
        
        Args:
            conversation_history: Previous messages
            
        Returns:
            Tuple[float, List[str]]: (score, risk_factors)
        """
        risk_factors = []
        score = 0.0
        
        # Check for escalation patterns - improved scoring
        if len(conversation_history) >= 2:
            # Look for increasing urgency or pressure
            recent_messages = conversation_history[-2:]
            urgency_count = 0
            
            for msg in recent_messages:
                content = msg.get('content', '').lower()
                if any(keyword in content for keyword in self.URGENCY_KEYWORDS):
                    urgency_count += 1
            
            if urgency_count >= 2:
                risk_factors.append("escalating_urgency")
                score += 0.25  # Increased from 0.15
        
        # Check for repeated financial requests - improved scoring
        financial_requests = 0
        for msg in conversation_history:
            content = msg.get('content', '').lower()
            if any(keyword in content for keyword in self.FINANCIAL_KEYWORDS):
                financial_requests += 1
        
        if financial_requests >= 2:
            risk_factors.append("repeated_financial_requests")
            score += 0.2  # Increased from 0.1
        
        # Check for information gathering progression - improved scoring
        contact_requests = 0
        for msg in conversation_history:
            content = msg.get('content', '')
            for pattern in self.compiled_patterns['contact_requests']:
                if pattern.search(content):
                    contact_requests += 1
                    break
        
        if contact_requests >= 1:
            risk_factors.append("progressive_info_gathering")
            score += 0.2  # Increased from 0.1
        
        # Check for authority claims progression
        authority_claims = 0
        authority_keywords = ['officer', 'manager', 'executive', 'representative', 'agent', 'official']
        for msg in conversation_history:
            content = msg.get('content', '').lower()
            if any(keyword in content for keyword in authority_keywords):
                authority_claims += 1
        
        if authority_claims >= 1:
            risk_factors.append("authority_claims_history")
            score += 0.15
        
        # Check for trust building attempts over time
        trust_attempts = 0
        trust_keywords = ['trust', 'honest', 'genuine', 'believe', 'legitimate']
        for msg in conversation_history:
            content = msg.get('content', '').lower()
            if any(keyword in content for keyword in trust_keywords):
                trust_attempts += 1
        
        if trust_attempts >= 1:
            risk_factors.append("trust_building_history")
            score += 0.15
        
        return min(score, 0.15), risk_factors
    
    def _analyze_ml_classification(
        self,
        message: str,
        conversation_history: List[Dict[str, Any]]
    ) -> Tuple[float, List[str]]:
        """
        Analyze message using ML classification.
        
        Args:
            message: Current message
            conversation_history: Previous messages
            
        Returns:
            Tuple[float, List[str]]: (score, risk_factors)
        """
        risk_factors = []
        score = 0.0
        
        if not self.ml_detector.is_trained:
            return score, risk_factors
        
        try:
            # Get conversation context
            conversation_texts = [msg.get('content', '') for msg in conversation_history]
            
            # Get ML prediction
            ml_prediction = self.ml_detector.predict(message, conversation_texts)
            
            # Convert ML probability to risk score
            ml_probability = ml_prediction.probability
            ml_confidence = ml_prediction.confidence
            
            # Scale ML probability to risk score (0.0 to 0.6 max for ML component)
            score = min(ml_probability * 0.6, 0.6)
            
            # Add risk factors based on ML prediction
            if ml_probability > 0.8:
                risk_factors.append("ml_high_scam_probability")
            elif ml_probability > 0.6:
                risk_factors.append("ml_medium_scam_probability")
            elif ml_probability > 0.4:
                risk_factors.append("ml_low_scam_probability")
            
            # Add factors based on individual model agreement
            model_predictions = ml_prediction.model_predictions
            high_confidence_models = [
                name for name, pred in model_predictions.items() 
                if pred > 0.7
            ]
            
            if len(high_confidence_models) >= 3:
                risk_factors.append("ml_multiple_models_agree")
                score *= 1.2  # Boost score when multiple models agree
            elif len(high_confidence_models) >= 2:
                risk_factors.append("ml_some_models_agree")
                score *= 1.1
            
            # Add factors based on important features
            feature_importance = ml_prediction.feature_importance
            if feature_importance:
                top_feature = max(feature_importance.keys(), key=lambda k: feature_importance[k])
                if 'financial' in top_feature or 'money' in top_feature:
                    risk_factors.append("ml_financial_features_important")
                elif 'urgency' in top_feature or 'urgent' in top_feature:
                    risk_factors.append("ml_urgency_features_important")
                elif 'trust' in top_feature or 'authority' in top_feature:
                    risk_factors.append("ml_social_engineering_features_important")
            
            # Adjust score based on ML confidence
            if ml_confidence > 0.8:
                score *= 1.1  # Boost for high confidence
            elif ml_confidence < 0.5:
                score *= 0.8  # Reduce for low confidence
            
        except Exception as e:
            logger.warning(f"ML classification failed: {e}")
            # Return minimal score on error
            score = 0.05
            risk_factors.append("ml_classification_error")
        
        return min(score, 0.6), risk_factors
    
    def _categorize_risk_factors(self, risk_factors: List[str]) -> Dict[str, List[str]]:
        """
        Categorize risk factors by type for audit logging.
        
        Args:
            risk_factors: List of risk factors
            
        Returns:
            Dict[str, List[str]]: Categorized risk factors
        """
        categories = {
            'financial': [],
            'urgency': [],
            'social_engineering': [],
            'information_gathering': [],
            'suspicious_patterns': [],
            'ml_indicators': [],
            'temporal_patterns': [],
            'conversation_flow': [],
            'cross_session': []
        }
        
        for factor in risk_factors:
            factor_lower = factor.lower()
            
            if any(keyword in factor_lower for keyword in ['financial', 'money', 'payment', 'bank', 'upi']):
                categories['financial'].append(factor)
            elif any(keyword in factor_lower for keyword in ['urgency', 'urgent', 'immediate', 'emergency']):
                categories['urgency'].append(factor)
            elif any(keyword in factor_lower for keyword in ['social', 'trust', 'authority', 'fear', 'engineering']):
                categories['social_engineering'].append(factor)
            elif any(keyword in factor_lower for keyword in ['contact', 'info', 'request', 'gathering']):
                categories['information_gathering'].append(factor)
            elif any(keyword in factor_lower for keyword in ['phone', 'url', 'email', 'pattern', 'caps', 'punctuation']):
                categories['suspicious_patterns'].append(factor)
            elif any(keyword in factor_lower for keyword in ['ml_', 'model', 'prediction']):
                categories['ml_indicators'].append(factor)
            elif any(keyword in factor_lower for keyword in ['frequency', 'timing', 'velocity', 'response']):
                categories['temporal_patterns'].append(factor)
            elif any(keyword in factor_lower for keyword in ['topic', 'pressure', 'stage', 'tactic', 'flow']):
                categories['conversation_flow'].append(factor)
            elif any(keyword in factor_lower for keyword in ['session', 'pattern', 'entity', 'overlap']):
                categories['cross_session'].append(factor)
        
        # Remove empty categories
        return {k: v for k, v in categories.items() if v}
    
    def _extract_risk_categories(self, risk_factors: List[str]) -> List[str]:
        """
        Extract unique risk categories from risk factors.
        
        Args:
            risk_factors: List of risk factors
            
        Returns:
            List[str]: Unique risk categories
        """
        categories = set()
        
        for factor in risk_factors:
            factor_lower = factor.lower()
            
            if any(keyword in factor_lower for keyword in ['financial', 'money', 'payment', 'bank', 'upi']):
                categories.add('financial')
            elif any(keyword in factor_lower for keyword in ['urgency', 'urgent', 'immediate', 'emergency']):
                categories.add('urgency')
            elif any(keyword in factor_lower for keyword in ['social', 'trust', 'authority', 'fear', 'engineering']):
                categories.add('social_engineering')
            elif any(keyword in factor_lower for keyword in ['contact', 'info', 'request', 'gathering']):
                categories.add('information_gathering')
            elif any(keyword in factor_lower for keyword in ['phone', 'url', 'email', 'pattern', 'caps', 'punctuation']):
                categories.add('suspicious_patterns')
            elif any(keyword in factor_lower for keyword in ['ml_', 'model', 'prediction']):
                categories.add('ml_indicators')
        
        return list(categories)
    
    def _calculate_weighted_score(self, scores: List[float]) -> float:
        """
        Calculate weighted final score from component scores.
        
        Args:
            scores: List of component scores [rule_based, keyword, pattern, context, ml]
            
        Returns:
            float: Weighted final score
        """
        if not scores:
            return 0.0
        
        # Updated weights for different analysis components
        # Balanced weights between rule-based and ML approaches
        if len(scores) >= 5:  # All components including ML
            weights = [0.25, 0.25, 0.1, 0.05, 0.35]  # rule_based, keyword, pattern, context, ml
        else:
            # Fallback weights if ML is not available
            weights = [0.4, 0.35, 0.15, 0.1]  # rule_based, keyword, pattern, context
        
        # Ensure we have enough weights
        if len(scores) > len(weights):
            weights.extend([0.05] * (len(scores) - len(weights)))
        
        # Normalize weights
        total_weight = sum(weights[:len(scores)])
        normalized_weights = [w / total_weight for w in weights[:len(scores)]]
        
        # Calculate weighted sum
        weighted_score = sum(score * weight for score, weight in zip(scores, normalized_weights))
        
        # Apply boost for high individual scores - more aggressive
        max_score = max(scores) if scores else 0.0
        if max_score > 0.4:  # Lowered threshold from 0.5
            # Boost the final score if any component is high
            boost_factor = 1.0 + (max_score - 0.4) * 0.8  # Increased boost
            weighted_score *= boost_factor
        
        # Apply additional boost for multiple high scores - more aggressive
        high_scores = [s for s in scores if s > 0.2]  # Lowered threshold from 0.3
        if len(high_scores) >= 3:
            # Multiple high-risk components detected
            multi_factor_boost = 1.0 + (len(high_scores) - 2) * 0.25  # Increased boost
            weighted_score *= multi_factor_boost
        elif len(high_scores) >= 2:
            # Two high-risk components
            weighted_score *= 1.2  # Increased from 1.1
        
        # Special boost if both ML and rule-based are high
        if len(scores) >= 5:  # ML available
            ml_score = scores[4]  # ML is the 5th component
            rule_based_avg = sum(scores[:4]) / 4  # Average of rule-based components
            
            if ml_score > 0.3 and rule_based_avg > 0.2:  # Lowered thresholds
                # Both ML and rule-based indicate risk
                weighted_score *= 1.3  # Increased from 1.2
        
        return min(weighted_score, 1.0)
    
    def _calculate_confidence(self, scores: List[float], risk_factors: List[str]) -> float:
        """
        Calculate confidence level based on score consistency and evidence.
        
        Args:
            scores: Component scores
            risk_factors: Identified risk factors
            
        Returns:
            float: Confidence level (0.0-1.0)
        """
        if not scores:
            return 0.0
        
        # Base confidence from number of risk factors
        base_confidence = min(0.6, len(risk_factors) * 0.1)
        
        # Consistency bonus - lower variance in scores increases confidence
        if len(scores) > 1:
            mean_score = sum(scores) / len(scores)
            variance = sum((score - mean_score) ** 2 for score in scores) / len(scores)
            consistency_bonus = max(0.0, 0.3 - variance)
        else:
            consistency_bonus = 0.1
        
        # Evidence strength bonus
        high_value_factors = [
            'urgent_money_request', 'upi_id_detected', 'phone_number_detected',
            'contact_info_request', 'escalating_urgency'
        ]
        evidence_bonus = sum(0.05 for factor in risk_factors if factor in high_value_factors)
        
        total_confidence = base_confidence + consistency_bonus + evidence_bonus
        
        return min(1.0, total_confidence)


class LanguageDetector:
    """
    Simple language detection for English, Hindi, and Hinglish.
    """
    
    # Hindi script characters (Devanagari)
    HINDI_PATTERN = re.compile(r'[\u0900-\u097F]')
    
    # Common Hindi words in Roman script
    HINGLISH_WORDS = [
        'kya', 'hai', 'hain', 'kar', 'karo', 'kare', 'main', 'mein', 'aap', 'tum',
        'yeh', 'woh', 'koi', 'kuch', 'sab', 'sabhi', 'paisa', 'paise', 'rupaya',
        'bhejo', 'bhejiye', 'karo', 'kariye', 'batao', 'bataiye', 'samjha',
        'samjhe', 'theek', 'thik', 'accha', 'achha', 'bhai', 'dost', 'yaar'
    ]
    
    @classmethod
    def detect_language(cls, text: str) -> str:
        """
        Detect language of the text.
        
        Args:
            text: Text to analyze
            
        Returns:
            str: Detected language ('en', 'hi', or 'hinglish')
        """
        if not text:
            return 'en'
        
        text_lower = text.lower()
        
        # Check for Hindi script
        if cls.HINDI_PATTERN.search(text):
            return 'hi'
        
        # Check for Hinglish words
        hinglish_count = sum(1 for word in cls.HINGLISH_WORDS if word in text_lower)
        total_words = len(text_lower.split())
        
        if total_words > 0 and hinglish_count / total_words > 0.2:
            return 'hinglish'
        
        # Default to English
        return 'en'
    
    @classmethod
    def is_supported_language(cls, language: str) -> bool:
        """
        Check if language is supported.
        
        Args:
            language: Language code to check
            
        Returns:
            bool: True if supported
        """
        return language in ['en', 'hi', 'hinglish']