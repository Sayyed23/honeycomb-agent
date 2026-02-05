"""
Threat Intelligence Analysis System for Scammer Tactic Classification and Pattern Recognition.

This module implements sophisticated threat intelligence analysis including:
- Scammer tactic classification and pattern recognition
- Conversation analysis for methodology extraction
- Network analysis for connecting related entities across sessions
- Temporal and geographic correlation analysis

Requirements: 6.3
"""

import re
import logging
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import asyncio
from collections import defaultdict, Counter
import hashlib
import json

from app.core.logging import get_logger
from app.core.audit_logger import audit_logger
from app.database.models import Session, Message, ExtractedEntity, RiskAssessment
from app.database.connection import SessionLocal
from sqlalchemy import select, and_, or_, func
from sqlalchemy.orm import selectinload

logger = get_logger(__name__)


class ScammerTactic(Enum):
    """Enumeration of scammer tactics and methodologies."""
    URGENCY_CREATION = "urgency_creation"
    AUTHORITY_IMPERSONATION = "authority_impersonation"
    SOCIAL_PROOF = "social_proof"
    FEAR_INDUCTION = "fear_induction"
    TRUST_BUILDING = "trust_building"
    TECHNICAL_CONFUSION = "technical_confusion"
    FINANCIAL_INCENTIVE = "financial_incentive"
    EMOTIONAL_MANIPULATION = "emotional_manipulation"
    INFORMATION_HARVESTING = "information_harvesting"
    CREDENTIAL_PHISHING = "credential_phishing"


class ThreatSeverity(Enum):
    """Threat severity levels for intelligence assessment."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class MethodologyType(Enum):
    """Types of scammer methodologies."""
    FINANCIAL_FRAUD = "financial_fraud"
    IDENTITY_THEFT = "identity_theft"
    TECHNICAL_SUPPORT = "technical_support"
    ROMANCE_SCAM = "romance_scam"
    INVESTMENT_FRAUD = "investment_fraud"
    PHISHING = "phishing"
    SOCIAL_ENGINEERING = "social_engineering"
    ADVANCE_FEE = "advance_fee"


@dataclass
class TacticPattern:
    """Data structure for scammer tactic patterns."""
    tactic: ScammerTactic
    confidence: float
    indicators: List[str]
    context: str
    severity: ThreatSeverity
    methodology: MethodologyType
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ConversationAnalysis:
    """Analysis results for a conversation."""
    session_id: str
    tactics_detected: List[TacticPattern]
    methodology_classification: MethodologyType
    threat_score: float
    conversation_summary: str
    key_indicators: List[str]
    timeline_analysis: Dict[str, Any]
    entity_relationships: Dict[str, List[str]]


@dataclass
class NetworkConnection:
    """Connection between entities across sessions."""
    entity_value: str
    entity_type: str
    connected_sessions: List[str]
    connection_strength: float
    first_seen: datetime
    last_seen: datetime
    frequency: int
    threat_level: ThreatSeverity


@dataclass
class TemporalPattern:
    """Temporal pattern analysis results."""
    pattern_type: str
    time_window: str
    frequency: int
    sessions_involved: List[str]
    confidence: float
    threat_indicators: List[str]


@dataclass
class GeographicCorrelation:
    """Geographic correlation analysis results."""
    region_pattern: str
    session_count: int
    entity_overlap: int
    time_correlation: float
    threat_assessment: ThreatSeverity


class TacticClassifier:
    """Classifier for identifying scammer tactics in conversations."""
    
    def __init__(self):
        """Initialize the tactic classifier with pattern definitions."""
        self.tactic_patterns = self._initialize_tactic_patterns()
        self.methodology_indicators = self._initialize_methodology_indicators()
    
    def _initialize_tactic_patterns(self) -> Dict[ScammerTactic, List[Dict[str, Any]]]:
        """Initialize tactic detection patterns."""
        return {
            ScammerTactic.URGENCY_CREATION: [
                {
                    'patterns': [
                        r'\b(?:urgent|immediately|asap|right now|hurry|quick|fast|emergency)\b',
                        r'\b(?:limited time|expires|deadline|last chance|act now)\b',
                        r'\b(?:within \d+ (?:minutes|hours|days))\b'
                    ],
                    'weight': 0.8,
                    'context_boost': ['payment', 'transfer', 'account', 'verify']
                }
            ],
            ScammerTactic.AUTHORITY_IMPERSONATION: [
                {
                    'patterns': [
                        r'\b(?:bank|government|police|officer|manager|supervisor|admin)\b',
                        r'\b(?:official|authorized|certified|licensed|registered)\b',
                        r'\b(?:department|ministry|bureau|agency|institution)\b'
                    ],
                    'weight': 0.9,
                    'context_boost': ['verify', 'confirm', 'update', 'security']
                }
            ],
            ScammerTactic.SOCIAL_PROOF: [
                {
                    'patterns': [
                        r'\b(?:everyone|many people|customers|users|others)\b',
                        r'\b(?:popular|trending|recommended|trusted|verified)\b',
                        r'\b(?:thousands|millions|most people|majority)\b'
                    ],
                    'weight': 0.6,
                    'context_boost': ['using', 'doing', 'getting', 'earning']
                }
            ],
            ScammerTactic.FEAR_INDUCTION: [
                {
                    'patterns': [
                        r'\b(?:blocked|suspended|closed|terminated|cancelled)\b',
                        r'\b(?:fraud|illegal|criminal|violation|penalty|fine)\b',
                        r'\b(?:lose|lost|stolen|hacked|compromised|breach)\b'
                    ],
                    'weight': 0.85,
                    'context_boost': ['account', 'money', 'card', 'security']
                }
            ],
            ScammerTactic.TRUST_BUILDING: [
                {
                    'patterns': [
                        r'\b(?:trust|reliable|safe|secure|guaranteed|promise)\b',
                        r'\b(?:help|assist|support|guide|protect|care)\b',
                        r'\b(?:friend|family|personal|private|confidential)\b'
                    ],
                    'weight': 0.7,
                    'context_boost': ['you', 'your', 'personal', 'special']
                }
            ],
            ScammerTactic.TECHNICAL_CONFUSION: [
                {
                    'patterns': [
                        r'\b(?:technical|system|server|database|network|software)\b',
                        r'\b(?:error|bug|glitch|malfunction|update|upgrade)\b',
                        r'\b(?:code|token|otp|pin|password|verification)\b'
                    ],
                    'weight': 0.75,
                    'context_boost': ['fix', 'resolve', 'enter', 'provide']
                }
            ],
            ScammerTactic.FINANCIAL_INCENTIVE: [
                {
                    'patterns': [
                        r'\b(?:money|cash|profit|earn|income|reward|bonus)\b',
                        r'\b(?:free|discount|offer|deal|promotion|gift)\b',
                        r'\b(?:investment|return|interest|dividend|payout)\b'
                    ],
                    'weight': 0.8,
                    'context_boost': ['get', 'receive', 'win', 'claim']
                }
            ],
            ScammerTactic.EMOTIONAL_MANIPULATION: [
                {
                    'patterns': [
                        r'\b(?:love|care|miss|lonely|sad|worried|concerned)\b',
                        r'\b(?:family|mother|father|child|sick|hospital|emergency)\b',
                        r'\b(?:help|need|please|desperate|trouble|problem)\b'
                    ],
                    'weight': 0.7,
                    'context_boost': ['money', 'send', 'transfer', 'urgent']
                }
            ],
            ScammerTactic.INFORMATION_HARVESTING: [
                {
                    'patterns': [
                        r'\b(?:details|information|data|personal|private|confidential)\b',
                        r'\b(?:name|address|phone|email|date of birth|ssn|aadhar)\b',
                        r'\b(?:account|card|number|pin|password|otp|cvv)\b'
                    ],
                    'weight': 0.9,
                    'context_boost': ['provide', 'share', 'give', 'tell', 'confirm']
                }
            ],
            ScammerTactic.CREDENTIAL_PHISHING: [
                {
                    'patterns': [
                        r'\b(?:login|username|password|pin|otp|verification)\b',
                        r'\b(?:link|website|portal|page|form|submit)\b',
                        r'\b(?:click|visit|go to|open|access|enter)\b'
                    ],
                    'weight': 0.85,
                    'context_boost': ['verify', 'update', 'confirm', 'secure']
                }
            ]
        }
    
    def _initialize_methodology_indicators(self) -> Dict[MethodologyType, List[str]]:
        """Initialize methodology classification indicators."""
        return {
            MethodologyType.FINANCIAL_FRAUD: [
                'bank', 'account', 'transfer', 'payment', 'upi', 'card', 'loan'
            ],
            MethodologyType.IDENTITY_THEFT: [
                'personal', 'details', 'information', 'aadhar', 'pan', 'ssn', 'documents'
            ],
            MethodologyType.TECHNICAL_SUPPORT: [
                'computer', 'software', 'virus', 'technical', 'support', 'fix', 'error'
            ],
            MethodologyType.ROMANCE_SCAM: [
                'love', 'relationship', 'marry', 'meet', 'lonely', 'care', 'miss'
            ],
            MethodologyType.INVESTMENT_FRAUD: [
                'investment', 'profit', 'return', 'stock', 'trading', 'scheme', 'earn'
            ],
            MethodologyType.PHISHING: [
                'link', 'website', 'click', 'verify', 'update', 'login', 'portal'
            ],
            MethodologyType.SOCIAL_ENGINEERING: [
                'authority', 'official', 'government', 'police', 'manager', 'urgent'
            ],
            MethodologyType.ADVANCE_FEE: [
                'fee', 'advance', 'processing', 'tax', 'charge', 'payment', 'upfront'
            ]
        }
    
    def classify_tactics(self, messages: List[str], context: str = "") -> List[TacticPattern]:
        """
        Classify scammer tactics in conversation messages.
        
        Args:
            messages: List of conversation messages
            context: Additional context information
            
        Returns:
            List[TacticPattern]: Detected tactic patterns
        """
        detected_tactics = []
        combined_text = " ".join(messages).lower()
        
        for tactic, pattern_configs in self.tactic_patterns.items():
            for config in pattern_configs:
                confidence = 0.0
                matched_indicators = []
                
                # Check for pattern matches
                for pattern in config['patterns']:
                    matches = re.findall(pattern, combined_text, re.IGNORECASE)
                    if matches:
                        confidence += config['weight'] * (len(matches) / len(messages))
                        matched_indicators.extend(matches)
                
                # Apply context boost
                if 'context_boost' in config:
                    for boost_term in config['context_boost']:
                        if boost_term in combined_text:
                            confidence += 0.1
                
                # Normalize confidence
                confidence = min(confidence, 1.0)
                
                if confidence > 0.3:  # Minimum threshold for detection
                    # Determine severity and methodology
                    severity = self._determine_severity(tactic, confidence)
                    methodology = self._classify_methodology(combined_text)
                    
                    tactic_pattern = TacticPattern(
                        tactic=tactic,
                        confidence=confidence,
                        indicators=matched_indicators,
                        context=context,
                        severity=severity,
                        methodology=methodology,
                        metadata={
                            'message_count': len(messages),
                            'pattern_density': len(matched_indicators) / len(combined_text.split()),
                            'detection_timestamp': datetime.utcnow().isoformat()
                        }
                    )
                    
                    detected_tactics.append(tactic_pattern)
        
        return detected_tactics
    
    def _determine_severity(self, tactic: ScammerTactic, confidence: float) -> ThreatSeverity:
        """Determine threat severity based on tactic and confidence."""
        high_risk_tactics = {
            ScammerTactic.CREDENTIAL_PHISHING,
            ScammerTactic.INFORMATION_HARVESTING,
            ScammerTactic.AUTHORITY_IMPERSONATION
        }
        
        if tactic in high_risk_tactics and confidence > 0.7:
            return ThreatSeverity.CRITICAL
        elif confidence > 0.8:
            return ThreatSeverity.HIGH
        elif confidence > 0.6:
            return ThreatSeverity.MEDIUM
        else:
            return ThreatSeverity.LOW
    
    def _classify_methodology(self, text: str) -> MethodologyType:
        """Classify the overall scammer methodology."""
        methodology_scores = {}
        
        for methodology, indicators in self.methodology_indicators.items():
            score = 0
            for indicator in indicators:
                if indicator in text:
                    score += 1
            methodology_scores[methodology] = score / len(indicators)
        
        # Return methodology with highest score
        if methodology_scores:
            best_methodology = max(methodology_scores, key=methodology_scores.get)
            if methodology_scores[best_methodology] > 0.1:
                return best_methodology
        
        return MethodologyType.SOCIAL_ENGINEERING  # Default


class ConversationAnalyzer:
    """Analyzer for extracting methodologies and patterns from conversations."""
    
    def __init__(self):
        """Initialize the conversation analyzer."""
        self.tactic_classifier = TacticClassifier()
    
    async def analyze_conversation(self, session_id: str) -> ConversationAnalysis:
        """
        Analyze a complete conversation for tactics and methodologies.
        
        Args:
            session_id: Session identifier
            
        Returns:
            ConversationAnalysis: Comprehensive conversation analysis
        """
        try:
            # Simplified conversation analysis (no database dependency)
            logger.info(f"Analyzing conversation for session {session_id}")
            
            # Get session logic
            with SessionLocal() as db_session:
                # Get session with messages and entities
                result = db_session.execute(
                    select(Session)
                    .options(
                        selectinload(Session.messages),
                        selectinload(Session.entities)
                    )
                    .where(Session.session_id == session_id)
                )
                session = result.scalar_one_or_none()
                
                if not session:
                    logger.warning(f"Session not found: {session_id}")
                    return self._create_empty_analysis(session_id)
                
                # Extract messages
                messages = [msg.content for msg in session.messages if msg.role == 'user']
                
                if not messages:
                    logger.warning(f"No user messages found in session: {session_id}")
                    return self._create_empty_analysis(session_id)
                
                # Classify tactics
                tactics_detected = self.tactic_classifier.classify_tactics(messages)
                
                # Determine overall methodology
                methodology = self._determine_primary_methodology(tactics_detected)
                
                # Calculate threat score
                threat_score = self._calculate_threat_score(tactics_detected, session.risk_score)
                
                # Generate conversation summary
                conversation_summary = self._generate_conversation_summary(
                    messages, tactics_detected, methodology
                )
                
                # Extract key indicators
                key_indicators = self._extract_key_indicators(messages, tactics_detected)
                
                # Analyze timeline
                timeline_analysis = self._analyze_timeline(session.messages)
                
                # Analyze entity relationships
                entity_relationships = self._analyze_entity_relationships(session.entities)
                
                analysis = ConversationAnalysis(
                    session_id=session_id,
                    tactics_detected=tactics_detected,
                    methodology_classification=methodology,
                    threat_score=threat_score,
                    conversation_summary=conversation_summary,
                    key_indicators=key_indicators,
                    timeline_analysis=timeline_analysis,
                    entity_relationships=entity_relationships
                )
                
                # Log analysis
                await self._log_conversation_analysis(analysis)
                
                return analysis
                
        except Exception as e:
            logger.error(f"Error analyzing conversation {session_id}: {e}", exc_info=True)
            return self._create_empty_analysis(session_id)
    
    def _create_empty_analysis(self, session_id: str) -> ConversationAnalysis:
        """Create empty analysis for error cases."""
        return ConversationAnalysis(
            session_id=session_id,
            tactics_detected=[],
            methodology_classification=MethodologyType.SOCIAL_ENGINEERING,
            threat_score=0.0,
            conversation_summary="No analysis available",
            key_indicators=[],
            timeline_analysis={},
            entity_relationships={}
        )
    
    def _determine_primary_methodology(self, tactics: List[TacticPattern]) -> MethodologyType:
        """Determine the primary methodology from detected tactics."""
        if not tactics:
            return MethodologyType.SOCIAL_ENGINEERING
        
        # Count methodology occurrences
        methodology_counts = Counter(tactic.methodology for tactic in tactics)
        
        # Weight by confidence
        methodology_scores = defaultdict(float)
        for tactic in tactics:
            methodology_scores[tactic.methodology] += tactic.confidence
        
        # Return methodology with highest weighted score
        if methodology_scores:
            return max(methodology_scores, key=methodology_scores.get)
        
        return MethodologyType.SOCIAL_ENGINEERING
    
    def _calculate_threat_score(self, tactics: List[TacticPattern], base_risk_score: float) -> float:
        """Calculate overall threat score for the conversation."""
        if not tactics:
            return base_risk_score
        
        # Base score from risk assessment
        threat_score = base_risk_score
        
        # Add tactic-based scoring
        tactic_score = sum(tactic.confidence for tactic in tactics) / len(tactics)
        threat_score = (threat_score + tactic_score) / 2
        
        # Boost for high-severity tactics
        critical_tactics = [t for t in tactics if t.severity == ThreatSeverity.CRITICAL]
        if critical_tactics:
            threat_score = min(threat_score + 0.2, 1.0)
        
        return threat_score
    
    def _generate_conversation_summary(
        self,
        messages: List[str],
        tactics: List[TacticPattern],
        methodology: MethodologyType
    ) -> str:
        """Generate a summary of the conversation analysis."""
        tactic_names = [tactic.tactic.value.replace('_', ' ').title() for tactic in tactics]
        
        summary = f"Conversation classified as {methodology.value.replace('_', ' ').title()} "
        summary += f"with {len(tactics)} tactics detected: {', '.join(tactic_names[:3])}"
        
        if len(tactic_names) > 3:
            summary += f" and {len(tactic_names) - 3} others"
        
        return summary
    
    def _extract_key_indicators(
        self,
        messages: List[str],
        tactics: List[TacticPattern]
    ) -> List[str]:
        """Extract key indicators from the conversation."""
        indicators = set()
        
        # Add tactic indicators
        for tactic in tactics:
            indicators.update(tactic.indicators[:2])  # Top 2 indicators per tactic
        
        # Add high-frequency terms
        combined_text = " ".join(messages).lower()
        words = re.findall(r'\b\w+\b', combined_text)
        word_counts = Counter(words)
        
        # Add most common suspicious words
        suspicious_words = [
            'money', 'payment', 'transfer', 'account', 'verify', 'urgent',
            'bank', 'card', 'otp', 'pin', 'password', 'link', 'click'
        ]
        
        for word in suspicious_words:
            if word_counts.get(word, 0) > 1:
                indicators.add(word)
        
        return list(indicators)[:10]  # Return top 10 indicators
    
    def _analyze_timeline(self, messages: List[Message]) -> Dict[str, Any]:
        """Analyze conversation timeline patterns."""
        if len(messages) < 2:
            return {}
        
        # Calculate message intervals
        intervals = []
        for i in range(1, len(messages)):
            interval = (messages[i].timestamp - messages[i-1].timestamp).total_seconds()
            intervals.append(interval)
        
        return {
            'total_duration_seconds': (messages[-1].timestamp - messages[0].timestamp).total_seconds(),
            'message_count': len(messages),
            'average_interval_seconds': sum(intervals) / len(intervals) if intervals else 0,
            'min_interval_seconds': min(intervals) if intervals else 0,
            'max_interval_seconds': max(intervals) if intervals else 0,
            'rapid_responses': len([i for i in intervals if i < 30]),  # Responses under 30 seconds
            'conversation_pace': 'fast' if sum(intervals) / len(intervals) < 60 else 'normal'
        }
    
    def _analyze_entity_relationships(self, entities: List[ExtractedEntity]) -> Dict[str, List[str]]:
        """Analyze relationships between extracted entities."""
        relationships = defaultdict(list)
        
        # Group entities by type
        entity_groups = defaultdict(list)
        for entity in entities:
            entity_groups[entity.entity_type].append(entity.entity_value)
        
        # Create relationships
        for entity_type, values in entity_groups.items():
            if len(values) > 1:
                relationships[f"multiple_{entity_type}"] = values
        
        # Cross-type relationships
        if 'upi_id' in entity_groups and 'phone_number' in entity_groups:
            relationships['financial_contact_link'] = entity_groups['upi_id'] + entity_groups['phone_number']
        
        return dict(relationships)
    
    async def _log_conversation_analysis(self, analysis: ConversationAnalysis) -> None:
        """Log conversation analysis for audit purposes."""
        try:
            audit_logger.log_threat_intelligence(
                session_id=analysis.session_id,
                analysis_type="conversation_analysis",
                threat_score=analysis.threat_score,
                methodology=analysis.methodology_classification.value,
                tactics_detected=[t.tactic.value for t in analysis.tactics_detected],
                key_indicators=analysis.key_indicators,
                analysis_summary=analysis.conversation_summary
            )
        except Exception as e:
            logger.error(f"Error logging conversation analysis: {e}", exc_info=True)


class NetworkAnalyzer:
    """Analyzer for connecting related entities across sessions."""
    
    def __init__(self):
        """Initialize the network analyzer."""
        self.connection_cache = {}
        self.analysis_cache = {}
    
    async def analyze_entity_networks(
        self,
        lookback_days: int = 30,
        min_connection_strength: float = 0.5
    ) -> List[NetworkConnection]:
        """
        Analyze entity networks across sessions to identify connections.
        
        Args:
            lookback_days: Number of days to look back for analysis
            min_connection_strength: Minimum connection strength threshold
            
        Returns:
            List[NetworkConnection]: Network connections found
        """
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=lookback_days)
            
            with SessionLocal() as db_session:
                # Get entities from recent sessions
                result = db_session.execute(
                    select(ExtractedEntity, Session.session_id)
                    .join(Session, ExtractedEntity.session_id == Session.id)
                    .where(Session.created_at >= cutoff_date)
                    .where(ExtractedEntity.confidence_score >= 0.8)
                )
                
                entity_data = result.all()
                
                if not entity_data:
                    return []
                
                # Group entities by value and type
                entity_groups = defaultdict(list)
                for entity, session_id in entity_data:
                    key = (entity.entity_value, entity.entity_type)
                    entity_groups[key].append({
                        'session_id': session_id,
                        'created_at': entity.created_at,
                        'confidence': entity.confidence_score
                    })
                
                # Analyze connections
                connections = []
                for (entity_value, entity_type), occurrences in entity_groups.items():
                    if len(occurrences) > 1:  # Entity appears in multiple sessions
                        connection = await self._analyze_entity_connection(
                            entity_value, entity_type, occurrences
                        )
                        
                        if connection.connection_strength >= min_connection_strength:
                            connections.append(connection)
                
                # Sort by connection strength
                connections.sort(key=lambda x: x.connection_strength, reverse=True)
                
                # Log network analysis
                await self._log_network_analysis(connections, lookback_days)
                
                return connections
                
        except Exception as e:
            logger.error(f"Error analyzing entity networks: {e}", exc_info=True)
            return []
    
    async def _analyze_entity_connection(
        self,
        entity_value: str,
        entity_type: str,
        occurrences: List[Dict[str, Any]]
    ) -> NetworkConnection:
        """Analyze connection strength for a specific entity."""
        sessions = [occ['session_id'] for occ in occurrences]
        timestamps = [occ['created_at'] for occ in occurrences]
        confidences = [occ['confidence'] for occ in occurrences]
        
        # Calculate connection strength
        frequency_score = min(len(occurrences) / 10.0, 1.0)  # Normalize to max 10 occurrences
        confidence_score = sum(confidences) / len(confidences)
        
        # Time distribution score (more spread out = higher strength)
        time_span = (max(timestamps) - min(timestamps)).total_seconds()
        time_score = min(time_span / (7 * 24 * 3600), 1.0)  # Normalize to 1 week
        
        connection_strength = (frequency_score + confidence_score + time_score) / 3
        
        # Determine threat level
        threat_level = self._determine_network_threat_level(
            entity_type, connection_strength, len(occurrences)
        )
        
        return NetworkConnection(
            entity_value=entity_value,
            entity_type=entity_type,
            connected_sessions=sessions,
            connection_strength=connection_strength,
            first_seen=min(timestamps),
            last_seen=max(timestamps),
            frequency=len(occurrences),
            threat_level=threat_level
        )
    
    def _determine_network_threat_level(
        self,
        entity_type: str,
        connection_strength: float,
        frequency: int
    ) -> ThreatSeverity:
        """Determine threat level for network connections."""
        # High-risk entity types
        if entity_type in ['upi_id', 'bank_account'] and frequency >= 3:
            return ThreatSeverity.CRITICAL
        elif entity_type == 'phone_number' and frequency >= 5:
            return ThreatSeverity.HIGH
        elif connection_strength > 0.8:
            return ThreatSeverity.HIGH
        elif connection_strength > 0.6:
            return ThreatSeverity.MEDIUM
        else:
            return ThreatSeverity.LOW
    
    async def _log_network_analysis(
        self,
        connections: List[NetworkConnection],
        lookback_days: int
    ) -> None:
        """Log network analysis results."""
        try:
            audit_logger.log_threat_intelligence(
                session_id="network_analysis",
                analysis_type="entity_network_analysis",
                threat_score=len([c for c in connections if c.threat_level in [ThreatSeverity.CRITICAL, ThreatSeverity.HIGH]]) / max(len(connections), 1),
                methodology="network_correlation",
                tactics_detected=[],
                key_indicators=[c.entity_value for c in connections[:5]],
                analysis_summary=f"Analyzed {len(connections)} entity connections over {lookback_days} days"
            )
        except Exception as e:
            logger.error(f"Error logging network analysis: {e}", exc_info=True)


class GeographicAnalyzer:
    """Analyzer for geographic patterns and correlations."""
    
    def __init__(self):
        """Initialize the geographic analyzer."""
        self.ip_to_region_cache = {}
        self.region_patterns = {}
    
    async def analyze_geographic_correlations(
        self,
        lookback_days: int = 30
    ) -> List[GeographicCorrelation]:
        """
        Analyze geographic correlations in scammer activities.
        
        Args:
            lookback_days: Number of days to analyze
            
        Returns:
            List[GeographicCorrelation]: Geographic correlation patterns
        """
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=lookback_days)
            
            with SessionLocal() as db_session:
                # Get sessions with metadata containing IP information
                result = db_session.execute(
                    select(Session, Message)
                    .join(Message, Session.id == Message.session_id)
                    .where(Session.created_at >= cutoff_date)
                    .where(Session.risk_score >= 0.7)
                    .where(Message.message_metadata.isnot(None))
                )
                
                session_data = result.all()
                
                if not session_data:
                    return []
                
                # Extract geographic information
                geographic_data = await self._extract_geographic_data(session_data)
                
                # Analyze correlations
                correlations = await self._analyze_correlations(geographic_data)
                
                # Log geographic analysis
                await self._log_geographic_analysis(correlations, lookback_days)
                
                return correlations
                
        except Exception as e:
            logger.error(f"Error analyzing geographic correlations: {e}", exc_info=True)
            return []
    
    async def _extract_geographic_data(self, session_data: List[Tuple]) -> Dict[str, Any]:
        """Extract geographic information from session data."""
        geographic_info = defaultdict(lambda: {
            'sessions': [],
            'entities': set(),
            'timestamps': [],
            'risk_scores': []
        })
        
        for session, message in session_data:
            # Extract IP address from metadata
            ip_address = None
            if message.message_metadata:
                ip_address = message.message_metadata.get('ipAddress')
            
            if ip_address:
                # Get region from IP (simplified - in production would use GeoIP service)
                region = await self._get_region_from_ip(ip_address)
                
                if region:
                    geographic_info[region]['sessions'].append(session.session_id)
                    geographic_info[region]['timestamps'].append(session.created_at)
                    geographic_info[region]['risk_scores'].append(session.risk_score)
                    
                    # Add entities from this session
                    for entity in session.entities:
                        geographic_info[region]['entities'].add(
                            f"{entity.entity_type}:{entity.entity_value}"
                        )
        
        return dict(geographic_info)
    
    async def _get_region_from_ip(self, ip_address: str) -> Optional[str]:
        """
        Get geographic region from IP address.
        
        This is a simplified implementation. In production, you would use
        a proper GeoIP service like MaxMind or similar.
        """
        if ip_address in self.ip_to_region_cache:
            return self.ip_to_region_cache[ip_address]
        
        # Simplified region mapping based on IP ranges
        # In production, use proper GeoIP database
        region = self._simple_ip_to_region(ip_address)
        
        if region:
            self.ip_to_region_cache[ip_address] = region
        
        return region
    
    def _simple_ip_to_region(self, ip_address: str) -> Optional[str]:
        """
        Simple IP to region mapping for demonstration.
        In production, use proper GeoIP service.
        """
        try:
            # Parse IP address
            parts = ip_address.split('.')
            if len(parts) != 4:
                return None
            
            # Validate each octet
            for part in parts:
                octet = int(part)
                if octet < 0 or octet > 255:
                    return None
            
            first_octet = int(parts[0])
            
            # Simplified regional mapping based on first octet
            # This is for demonstration only - not accurate
            if first_octet in range(1, 50):
                return "North America"
            elif first_octet in range(50, 100):
                return "Europe"
            elif first_octet in range(100, 150):
                return "Asia Pacific"
            elif first_octet in range(150, 200):
                return "South Asia"
            elif first_octet in range(200, 255):
                return "Other Regions"
            
            return "Unknown"
            
        except (ValueError, IndexError):
            return None
    
    async def _analyze_correlations(
        self,
        geographic_data: Dict[str, Any]
    ) -> List[GeographicCorrelation]:
        """Analyze correlations between geographic regions."""
        correlations = []
        
        for region, data in geographic_data.items():
            if len(data['sessions']) < 2:  # Need at least 2 sessions for correlation
                continue
            
            # Calculate entity overlap with other regions
            entity_overlap = 0
            for other_region, other_data in geographic_data.items():
                if region != other_region:
                    overlap = len(data['entities'].intersection(other_data['entities']))
                    entity_overlap += overlap
            
            # Calculate time correlation (sessions clustered in time)
            time_correlation = self._calculate_time_correlation(data['timestamps'])
            
            # Determine threat assessment
            threat_assessment = self._assess_regional_threat(
                len(data['sessions']), entity_overlap, time_correlation, data['risk_scores']
            )
            
            correlation = GeographicCorrelation(
                region_pattern=region,
                session_count=len(data['sessions']),
                entity_overlap=entity_overlap,
                time_correlation=time_correlation,
                threat_assessment=threat_assessment
            )
            
            correlations.append(correlation)
        
        # Sort by threat level and session count
        correlations.sort(
            key=lambda x: (x.threat_assessment.value, x.session_count),
            reverse=True
        )
        
        return correlations
    
    def _calculate_time_correlation(self, timestamps: List[datetime]) -> float:
        """Calculate time correlation score for timestamps."""
        if len(timestamps) < 2:
            return 0.0
        
        # Sort timestamps
        sorted_timestamps = sorted(timestamps)
        
        # Calculate average time between sessions
        intervals = []
        for i in range(1, len(sorted_timestamps)):
            interval = (sorted_timestamps[i] - sorted_timestamps[i-1]).total_seconds()
            intervals.append(interval)
        
        if not intervals:
            return 0.0
        
        avg_interval = sum(intervals) / len(intervals)
        
        # Higher correlation for shorter intervals (more clustered)
        # Normalize to 0-1 scale where 1 hour = 0.5, 1 day = 0.1
        correlation = max(0.0, 1.0 - (avg_interval / 86400))  # 86400 seconds in a day
        
        return min(correlation, 1.0)
    
    def _assess_regional_threat(
        self,
        session_count: int,
        entity_overlap: int,
        time_correlation: float,
        risk_scores: List[float]
    ) -> ThreatSeverity:
        """Assess threat level for a geographic region."""
        # Calculate average risk score
        avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0.0
        
        # Threat assessment based on multiple factors
        threat_score = 0.0
        
        # Session count factor
        if session_count >= 10:
            threat_score += 0.4
        elif session_count >= 5:
            threat_score += 0.2
        
        # Entity overlap factor
        if entity_overlap >= 5:
            threat_score += 0.3
        elif entity_overlap >= 2:
            threat_score += 0.1
        
        # Time correlation factor
        threat_score += time_correlation * 0.2
        
        # Risk score factor
        threat_score += avg_risk * 0.1
        
        # Determine threat level
        if threat_score >= 0.8:
            return ThreatSeverity.CRITICAL
        elif threat_score >= 0.6:
            return ThreatSeverity.HIGH
        elif threat_score >= 0.4:
            return ThreatSeverity.MEDIUM
        else:
            return ThreatSeverity.LOW
    
    async def _log_geographic_analysis(
        self,
        correlations: List[GeographicCorrelation],
        lookback_days: int
    ) -> None:
        """Log geographic analysis results."""
        try:
            audit_logger.log_threat_intelligence(
                session_id="geographic_analysis",
                analysis_type="geographic_correlation_analysis",
                threat_score=len([c for c in correlations if c.threat_assessment in [ThreatSeverity.CRITICAL, ThreatSeverity.HIGH]]) / max(len(correlations), 1),
                methodology="geographic_correlation",
                tactics_detected=[],
                key_indicators=[c.region_pattern for c in correlations[:5]],
                analysis_summary=f"Analyzed {len(correlations)} geographic regions over {lookback_days} days"
            )
        except Exception as e:
            logger.error(f"Error logging geographic analysis: {e}", exc_info=True)


class TemporalAnalyzer:
    """Analyzer for temporal patterns and correlations."""
    
    def __init__(self):
        """Initialize the temporal analyzer."""
        pass
    
    async def analyze_temporal_patterns(
        self,
        lookback_days: int = 30
    ) -> List[TemporalPattern]:
        """
        Analyze temporal patterns in scammer activities.
        
        Args:
            lookback_days: Number of days to analyze
            
        Returns:
            List[TemporalPattern]: Detected temporal patterns
        """
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=lookback_days)
            
            with SessionLocal() as db_session:
                # Get sessions with high risk scores
                result = db_session.execute(
                    select(Session)
                    .where(Session.created_at >= cutoff_date)
                    .where(Session.risk_score >= 0.7)
                    .order_by(Session.created_at)
                )
                
                sessions = result.scalars().all()
                
                if len(sessions) < 3:
                    return []
                
                patterns = []
                
                # Analyze hourly patterns
                hourly_pattern = await self._analyze_hourly_patterns(sessions)
                if hourly_pattern:
                    patterns.append(hourly_pattern)
                
                # Analyze daily patterns
                daily_pattern = await self._analyze_daily_patterns(sessions)
                if daily_pattern:
                    patterns.append(daily_pattern)
                
                # Analyze burst patterns
                burst_patterns = await self._analyze_burst_patterns(sessions)
                patterns.extend(burst_patterns)
                
                # Log temporal analysis
                await self._log_temporal_analysis(patterns, lookback_days)
                
                return patterns
                
        except Exception as e:
            logger.error(f"Error analyzing temporal patterns: {e}", exc_info=True)
            return []
    
    async def _analyze_hourly_patterns(self, sessions: List[Session]) -> Optional[TemporalPattern]:
        """Analyze hourly activity patterns."""
        hour_counts = defaultdict(int)
        session_hours = defaultdict(list)
        
        for session in sessions:
            hour = session.created_at.hour
            hour_counts[hour] += 1
            session_hours[hour].append(session.session_id)
        
        # Find peak hours (above average + 1 std dev)
        if len(hour_counts) < 3:
            return None
        
        counts = list(hour_counts.values())
        avg_count = sum(counts) / len(counts)
        std_dev = (sum((x - avg_count) ** 2 for x in counts) / len(counts)) ** 0.5
        
        peak_threshold = avg_count + std_dev
        peak_hours = [hour for hour, count in hour_counts.items() if count > peak_threshold]
        
        if peak_hours:
            peak_sessions = []
            for hour in peak_hours:
                peak_sessions.extend(session_hours[hour])
            
            return TemporalPattern(
                pattern_type="hourly_peak",
                time_window=f"Hours: {', '.join(map(str, peak_hours))}",
                frequency=sum(hour_counts[hour] for hour in peak_hours),
                sessions_involved=peak_sessions,
                confidence=min(len(peak_hours) / 24.0 * 2, 1.0),
                threat_indicators=[f"Peak activity at hour {hour}" for hour in peak_hours]
            )
        
        return None
    
    async def _analyze_daily_patterns(self, sessions: List[Session]) -> Optional[TemporalPattern]:
        """Analyze daily activity patterns."""
        day_counts = defaultdict(int)
        session_days = defaultdict(list)
        
        for session in sessions:
            day = session.created_at.weekday()  # 0=Monday, 6=Sunday
            day_counts[day] += 1
            session_days[day].append(session.session_id)
        
        # Find peak days
        if len(day_counts) < 3:
            return None
        
        counts = list(day_counts.values())
        avg_count = sum(counts) / len(counts)
        
        peak_days = [day for day, count in day_counts.items() if count > avg_count * 1.5]
        
        if peak_days:
            day_names = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
            peak_day_names = [day_names[day] for day in peak_days]
            
            peak_sessions = []
            for day in peak_days:
                peak_sessions.extend(session_days[day])
            
            return TemporalPattern(
                pattern_type="daily_peak",
                time_window=f"Days: {', '.join(peak_day_names)}",
                frequency=sum(day_counts[day] for day in peak_days),
                sessions_involved=peak_sessions,
                confidence=min(len(peak_days) / 7.0 * 2, 1.0),
                threat_indicators=[f"Peak activity on {name}" for name in peak_day_names]
            )
        
        return None
    
    async def _analyze_burst_patterns(self, sessions: List[Session]) -> List[TemporalPattern]:
        """Analyze burst activity patterns."""
        patterns = []
        
        # Sort sessions by timestamp
        sorted_sessions = sorted(sessions, key=lambda s: s.created_at)
        
        # Find bursts (multiple sessions within short time windows)
        burst_window = timedelta(hours=1)  # 1-hour window
        current_burst = []
        
        for i, session in enumerate(sorted_sessions):
            if not current_burst:
                current_burst = [session]
                continue
            
            # Check if session is within burst window
            time_diff = session.created_at - current_burst[-1].created_at
            
            if time_diff <= burst_window:
                current_burst.append(session)
            else:
                # Process completed burst
                if len(current_burst) >= 3:  # Minimum 3 sessions for a burst
                    burst_pattern = TemporalPattern(
                        pattern_type="activity_burst",
                        time_window=f"{current_burst[0].created_at.strftime('%Y-%m-%d %H:%M')} - {current_burst[-1].created_at.strftime('%H:%M')}",
                        frequency=len(current_burst),
                        sessions_involved=[s.session_id for s in current_burst],
                        confidence=min(len(current_burst) / 10.0, 1.0),
                        threat_indicators=[f"Burst of {len(current_burst)} sessions in {time_diff.total_seconds()/60:.0f} minutes"]
                    )
                    patterns.append(burst_pattern)
                
                # Start new burst
                current_burst = [session]
        
        # Process final burst
        if len(current_burst) >= 3:
            time_span = current_burst[-1].created_at - current_burst[0].created_at
            burst_pattern = TemporalPattern(
                pattern_type="activity_burst",
                time_window=f"{current_burst[0].created_at.strftime('%Y-%m-%d %H:%M')} - {current_burst[-1].created_at.strftime('%H:%M')}",
                frequency=len(current_burst),
                sessions_involved=[s.session_id for s in current_burst],
                confidence=min(len(current_burst) / 10.0, 1.0),
                threat_indicators=[f"Burst of {len(current_burst)} sessions in {time_span.total_seconds()/60:.0f} minutes"]
            )
            patterns.append(burst_pattern)
        
        return patterns
    
    async def _log_temporal_analysis(
        self,
        patterns: List[TemporalPattern],
        lookback_days: int
    ) -> None:
        """Log temporal analysis results."""
        try:
            audit_logger.log_threat_intelligence(
                session_id="temporal_analysis",
                analysis_type="temporal_pattern_analysis",
                threat_score=len(patterns) / 10.0,  # Normalize to number of patterns
                methodology="temporal_correlation",
                tactics_detected=[],
                key_indicators=[p.pattern_type for p in patterns],
                analysis_summary=f"Analyzed {len(patterns)} temporal patterns over {lookback_days} days"
            )
        except Exception as e:
            logger.error(f"Error logging temporal analysis: {e}", exc_info=True)


class ThreatIntelligenceEngine:
    """
    Main threat intelligence analysis engine that coordinates all analysis components.
    
    Provides high-level interface for threat intelligence analysis including
    tactic classification, conversation analysis, network analysis, temporal correlation,
    and geographic correlation analysis.
    """
    
    def __init__(self):
        """Initialize the threat intelligence engine."""
        self.conversation_analyzer = ConversationAnalyzer()
        self.network_analyzer = NetworkAnalyzer()
        self.temporal_analyzer = TemporalAnalyzer()
        self.geographic_analyzer = GeographicAnalyzer()
    
    async def analyze_session_intelligence(self, session_id: str) -> Dict[str, Any]:
        """
        Perform comprehensive threat intelligence analysis for a session.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Dict[str, Any]: Comprehensive intelligence analysis results
        """
        try:
            # Analyze conversation
            conversation_analysis = await self.conversation_analyzer.analyze_conversation(session_id)
            
            # Get related network connections
            network_connections = await self.network_analyzer.analyze_entity_networks(
                lookback_days=7,  # Shorter window for session-specific analysis
                min_connection_strength=0.3
            )
            
            # Filter connections relevant to this session
            relevant_connections = [
                conn for conn in network_connections
                if session_id in conn.connected_sessions
            ]
            
            # Compile intelligence report
            intelligence_report = {
                'session_id': session_id,
                'conversation_analysis': {
                    'tactics_detected': [
                        {
                            'tactic': tactic.tactic.value,
                            'confidence': tactic.confidence,
                            'severity': tactic.severity.value,
                            'indicators': tactic.indicators
                        }
                        for tactic in conversation_analysis.tactics_detected
                    ],
                    'methodology': conversation_analysis.methodology_classification.value,
                    'threat_score': conversation_analysis.threat_score,
                    'summary': conversation_analysis.conversation_summary,
                    'key_indicators': conversation_analysis.key_indicators,
                    'timeline_analysis': conversation_analysis.timeline_analysis
                },
                'network_connections': [
                    {
                        'entity_value': conn.entity_value,
                        'entity_type': conn.entity_type,
                        'connection_strength': conn.connection_strength,
                        'frequency': conn.frequency,
                        'threat_level': conn.threat_level.value,
                        'connected_sessions_count': len(conn.connected_sessions)
                    }
                    for conn in relevant_connections
                ],
                'intelligence_summary': self._generate_intelligence_summary(
                    conversation_analysis, relevant_connections
                ),
                'analysis_timestamp': datetime.utcnow().isoformat()
            }
            
            # Log intelligence analysis
            await self._log_intelligence_analysis(intelligence_report)
            
            return intelligence_report
            
        except Exception as e:
            logger.error(f"Error analyzing session intelligence {session_id}: {e}", exc_info=True)
            return {
                'session_id': session_id,
                'error': str(e),
                'analysis_timestamp': datetime.utcnow().isoformat()
            }
    
    async def generate_threat_intelligence_report(
        self,
        lookback_days: int = 30
    ) -> Dict[str, Any]:
        """
        Generate comprehensive threat intelligence report.
        
        Args:
            lookback_days: Number of days to analyze
            
        Returns:
            Dict[str, Any]: Comprehensive threat intelligence report
        """
        try:
            # Analyze network connections
            network_connections = await self.network_analyzer.analyze_entity_networks(lookback_days)
            
            # Analyze temporal patterns
            temporal_patterns = await self.temporal_analyzer.analyze_temporal_patterns(lookback_days)
            
            # Analyze geographic correlations
            geographic_correlations = await self.geographic_analyzer.analyze_geographic_correlations(lookback_days)
            
            # Get high-risk sessions for analysis
            cutoff_date = datetime.utcnow() - timedelta(days=lookback_days)
            
            with SessionLocal() as db_session:
                result = db_session.execute(
                    select(Session.session_id)
                    .where(Session.created_at >= cutoff_date)
                    .where(Session.risk_score >= 0.8)
                    .limit(50)  # Limit for performance
                )
                high_risk_sessions = [row[0] for row in result.all()]
            
            # Analyze sample of high-risk conversations
            conversation_analyses = []
            for session_id in high_risk_sessions[:10]:  # Analyze top 10
                analysis = await self.conversation_analyzer.analyze_conversation(session_id)
                conversation_analyses.append(analysis)
            
            # Compile comprehensive report
            report = {
                'report_period': {
                    'start_date': (datetime.utcnow() - timedelta(days=lookback_days)).isoformat(),
                    'end_date': datetime.utcnow().isoformat(),
                    'days_analyzed': lookback_days
                },
                'network_intelligence': {
                    'total_connections': len(network_connections),
                    'critical_connections': len([c for c in network_connections if c.threat_level == ThreatSeverity.CRITICAL]),
                    'high_risk_connections': len([c for c in network_connections if c.threat_level == ThreatSeverity.HIGH]),
                    'top_entities': [
                        {
                            'entity_value': conn.entity_value,
                            'entity_type': conn.entity_type,
                            'frequency': conn.frequency,
                            'threat_level': conn.threat_level.value
                        }
                        for conn in network_connections[:10]
                    ]
                },
                'temporal_intelligence': {
                    'patterns_detected': len(temporal_patterns),
                    'pattern_types': list(set(p.pattern_type for p in temporal_patterns)),
                    'high_confidence_patterns': [
                        {
                            'pattern_type': pattern.pattern_type,
                            'time_window': pattern.time_window,
                            'frequency': pattern.frequency,
                            'confidence': pattern.confidence
                        }
                        for pattern in temporal_patterns if pattern.confidence > 0.7
                    ]
                },
                'geographic_intelligence': {
                    'regions_analyzed': len(geographic_correlations),
                    'high_risk_regions': len([c for c in geographic_correlations if c.threat_assessment in [ThreatSeverity.CRITICAL, ThreatSeverity.HIGH]]),
                    'regional_patterns': [
                        {
                            'region': corr.region_pattern,
                            'session_count': corr.session_count,
                            'entity_overlap': corr.entity_overlap,
                            'threat_level': corr.threat_assessment.value,
                            'time_correlation': corr.time_correlation
                        }
                        for corr in geographic_correlations[:10]
                    ]
                },
                'conversation_intelligence': {
                    'sessions_analyzed': len(conversation_analyses),
                    'common_tactics': self._analyze_common_tactics(conversation_analyses),
                    'methodology_distribution': self._analyze_methodology_distribution(conversation_analyses),
                    'threat_score_distribution': self._analyze_threat_scores(conversation_analyses)
                },
                'key_findings': self._generate_key_findings(
                    network_connections, temporal_patterns, conversation_analyses, geographic_correlations
                ),
                'recommendations': self._generate_recommendations(
                    network_connections, temporal_patterns, conversation_analyses, geographic_correlations
                ),
                'report_timestamp': datetime.utcnow().isoformat()
            }
            
            # Log report generation
            await self._log_report_generation(report)
            
            return report
            
        except Exception as e:
            logger.error(f"Error generating threat intelligence report: {e}", exc_info=True)
            return {
                'error': str(e),
                'report_timestamp': datetime.utcnow().isoformat()
            }
    
    def _generate_intelligence_summary(
        self,
        conversation_analysis: ConversationAnalysis,
        network_connections: List[NetworkConnection]
    ) -> str:
        """Generate intelligence summary for a session."""
        summary_parts = []
        
        # Conversation summary
        summary_parts.append(f"Conversation: {conversation_analysis.conversation_summary}")
        
        # Network connections
        if network_connections:
            high_risk_connections = [c for c in network_connections if c.threat_level in [ThreatSeverity.CRITICAL, ThreatSeverity.HIGH]]
            if high_risk_connections:
                summary_parts.append(f"High-risk network connections: {len(high_risk_connections)} entities linked to other sessions")
        
        # Threat assessment
        if conversation_analysis.threat_score > 0.8:
            summary_parts.append("High threat level detected")
        elif conversation_analysis.threat_score > 0.6:
            summary_parts.append("Medium threat level detected")
        
        return ". ".join(summary_parts)
    
    def _analyze_common_tactics(self, analyses: List[ConversationAnalysis]) -> Dict[str, int]:
        """Analyze common tactics across conversations."""
        tactic_counts = Counter()
        
        for analysis in analyses:
            for tactic in analysis.tactics_detected:
                tactic_counts[tactic.tactic.value] += 1
        
        return dict(tactic_counts.most_common(10))
    
    def _analyze_methodology_distribution(self, analyses: List[ConversationAnalysis]) -> Dict[str, int]:
        """Analyze methodology distribution."""
        methodology_counts = Counter()
        
        for analysis in analyses:
            methodology_counts[analysis.methodology_classification.value] += 1
        
        return dict(methodology_counts)
    
    def _analyze_threat_scores(self, analyses: List[ConversationAnalysis]) -> Dict[str, int]:
        """Analyze threat score distribution."""
        score_ranges = {
            'critical (0.9-1.0)': 0,
            'high (0.7-0.9)': 0,
            'medium (0.5-0.7)': 0,
            'low (0.0-0.5)': 0
        }
        
        for analysis in analyses:
            score = analysis.threat_score
            if score >= 0.9:
                score_ranges['critical (0.9-1.0)'] += 1
            elif score >= 0.7:
                score_ranges['high (0.7-0.9)'] += 1
            elif score >= 0.5:
                score_ranges['medium (0.5-0.7)'] += 1
            else:
                score_ranges['low (0.0-0.5)'] += 1
        
        return score_ranges
    
    def _generate_key_findings(
        self,
        network_connections: List[NetworkConnection],
        temporal_patterns: List[TemporalPattern],
        conversation_analyses: List[ConversationAnalysis],
        geographic_correlations: List[GeographicCorrelation]
    ) -> List[str]:
        """Generate key findings from analysis."""
        findings = []
        
        # Network findings
        critical_entities = [c for c in network_connections if c.threat_level == ThreatSeverity.CRITICAL]
        if critical_entities:
            findings.append(f"Identified {len(critical_entities)} critical entities appearing across multiple sessions")
        
        # Temporal findings
        burst_patterns = [p for p in temporal_patterns if p.pattern_type == "activity_burst"]
        if burst_patterns:
            findings.append(f"Detected {len(burst_patterns)} activity burst patterns indicating coordinated attacks")
        
        # Geographic findings
        high_risk_regions = [c for c in geographic_correlations if c.threat_assessment in [ThreatSeverity.CRITICAL, ThreatSeverity.HIGH]]
        if high_risk_regions:
            findings.append(f"Identified {len(high_risk_regions)} high-risk geographic regions with coordinated scammer activity")
        
        # Conversation findings
        if conversation_analyses:
            avg_threat_score = sum(a.threat_score for a in conversation_analyses) / len(conversation_analyses)
            if avg_threat_score > 0.8:
                findings.append(f"High average threat score ({avg_threat_score:.2f}) across analyzed conversations")
        
        return findings
    
    def _generate_recommendations(
        self,
        network_connections: List[NetworkConnection],
        temporal_patterns: List[TemporalPattern],
        conversation_analyses: List[ConversationAnalysis],
        geographic_correlations: List[GeographicCorrelation]
    ) -> List[str]:
        """Generate recommendations based on analysis."""
        recommendations = []
        
        # Network-based recommendations
        high_frequency_entities = [c for c in network_connections if c.frequency >= 5]
        if high_frequency_entities:
            recommendations.append("Monitor high-frequency entities for potential scammer infrastructure")
        
        # Temporal-based recommendations
        if temporal_patterns:
            recommendations.append("Implement enhanced monitoring during identified peak activity periods")
        
        # Geographic-based recommendations
        critical_regions = [c for c in geographic_correlations if c.threat_assessment == ThreatSeverity.CRITICAL]
        if critical_regions:
            recommendations.append(f"Implement enhanced monitoring for traffic from {len(critical_regions)} high-risk geographic regions")
        
        # Conversation-based recommendations
        common_tactics = self._analyze_common_tactics(conversation_analyses)
        if common_tactics:
            top_tactic = max(common_tactics, key=common_tactics.get)
            recommendations.append(f"Enhance detection for {top_tactic.replace('_', ' ')} tactics")
        
        return recommendations
    
    async def _log_intelligence_analysis(self, report: Dict[str, Any]) -> None:
        """Log intelligence analysis for audit purposes."""
        try:
            audit_logger.log_threat_intelligence(
                session_id=report['session_id'],
                analysis_type="comprehensive_intelligence_analysis",
                threat_score=report.get('conversation_analysis', {}).get('threat_score', 0.0),
                methodology=report.get('conversation_analysis', {}).get('methodology', 'unknown'),
                tactics_detected=[t['tactic'] for t in report.get('conversation_analysis', {}).get('tactics_detected', [])],
                key_indicators=report.get('conversation_analysis', {}).get('key_indicators', []),
                analysis_summary=report.get('intelligence_summary', 'No summary available')
            )
        except Exception as e:
            logger.error(f"Error logging intelligence analysis: {e}", exc_info=True)
    
    async def _log_report_generation(self, report: Dict[str, Any]) -> None:
        """Log report generation for audit purposes."""
        try:
            audit_logger.log_threat_intelligence(
                session_id="threat_intelligence_report",
                analysis_type="comprehensive_threat_report",
                threat_score=len(report.get('key_findings', [])) / 10.0,
                methodology="multi_component_analysis",
                tactics_detected=[],
                key_indicators=report.get('key_findings', []),
                analysis_summary=f"Generated comprehensive threat intelligence report with {len(report.get('key_findings', []))} key findings"
            )
        except Exception as e:
            logger.error(f"Error logging report generation: {e}", exc_info=True)


# Global threat intelligence engine instance
threat_intelligence_engine = ThreatIntelligenceEngine()