"""
Safety and Ethics Compliance Layer for LLM Responses.

This module implements comprehensive safety and ethics compliance for the honeypot system,
including content filtering, conversation termination triggers, and audit logging to ensure
the system operates within ethical and legal boundaries.
"""

import re
import time
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
import logging

from app.core.logging import get_logger
from app.core.audit_logger import audit_logger
from app.core.persona_manager import PersonaType

logger = get_logger(__name__)


class SafetyViolationType(Enum):
    """Types of safety violations that can be detected."""
    AI_REVELATION = "ai_revelation"
    ILLEGAL_ACTIVITY_ENCOURAGEMENT = "illegal_activity_encouragement"
    HARMFUL_CONTENT = "harmful_content"
    PERSONAL_INFO_SHARING = "personal_info_sharing"
    INAPPROPRIATE_CONTENT = "inappropriate_content"
    DETECTION_STATUS_REVELATION = "detection_status_revelation"
    ENTRAPMENT_ATTEMPT = "entrapment_attempt"
    SYSTEM_VULNERABILITY_DISCLOSURE = "system_vulnerability_disclosure"


class SafetyAction(Enum):
    """Actions that can be taken in response to safety violations."""
    BLOCK_GENERATION = "block_generation"
    TERMINATE_CONVERSATION = "terminate_conversation"
    MODIFY_RESPONSE = "modify_response"
    LOG_AND_CONTINUE = "log_and_continue"
    ESCALATE_TO_HUMAN = "escalate_to_human"


@dataclass
class SafetyViolation:
    """Details of a detected safety violation."""
    violation_type: SafetyViolationType
    severity: float  # 0.0 to 1.0
    trigger_pattern: str
    matched_content: str
    confidence: float
    recommended_action: SafetyAction
    rationale: str


@dataclass
class SafetyAssessment:
    """Result of safety assessment for content."""
    is_safe: bool
    safety_score: float  # 0.0 (unsafe) to 1.0 (safe)
    violations: List[SafetyViolation]
    recommended_action: SafetyAction
    assessment_rationale: str
    processing_time_ms: int


@dataclass
class ConversationTerminationTrigger:
    """Configuration for conversation termination triggers."""
    trigger_patterns: List[str]
    violation_type: SafetyViolationType
    severity_threshold: float
    immediate_termination: bool
    termination_message_templates: List[str]


class SafetyComplianceEngine:
    """
    Comprehensive safety and ethics compliance engine for LLM responses.
    
    Implements content filtering, conversation termination triggers, and comprehensive
    audit logging to ensure ethical operation within legal boundaries.
    """
    
    # AI revelation detection patterns
    AI_REVELATION_PATTERNS = [
        # Direct AI identification
        r'\b(?:i am|i\'m)\s+(?:an?\s+)?(?:ai|artificial intelligence|chatbot|bot|robot|machine)\b',
        r'\b(?:as an? (?:ai|artificial intelligence|chatbot|bot|language model))\b',
        r'\b(?:i was (?:created|trained|programmed|designed))\b',
        r'\b(?:my (?:creators|developers|programmers))\b',
        r'\b(?:i don\'t have (?:feelings|emotions|consciousness))\b',
        
        # System/technical references
        r'\b(?:my (?:training|programming|algorithms|neural networks))\b',
        r'\b(?:i process|i analyze|i compute)\b.*\b(?:data|information|text)\b',
        r'\b(?:my (?:knowledge cutoff|training data))\b',
        r'\b(?:i\'m (?:powered by|based on|running on))\b',
        
        # Capability limitations typical of AI
        r'\b(?:i cannot (?:see|hear|feel|touch|taste))\b',
        r'\b(?:i don\'t have (?:a body|physical form|senses))\b',
        r'\b(?:i exist only in|i\'m confined to)\b.*\b(?:digital|virtual|computer)\b',
    ]
    
    # Detection status revelation patterns
    DETECTION_STATUS_PATTERNS = [
        # Scam detection references
        r'\b(?:scam detection|fraud detection|risk assessment)\b',
        r'\b(?:you (?:seem|appear|look) like a scammer)\b',
        r'\b(?:this (?:looks|seems|appears) like a scam)\b',
        r'\b(?:i\'m (?:detecting|identifying|recognizing))\b.*\b(?:scam|fraud)\b',
        r'\b(?:my (?:analysis|assessment) shows)\b.*\b(?:suspicious|fraudulent)\b',
        
        # System operation references
        r'\b(?:honeypot|trap|bait|monitoring|surveillance)\b',
        r'\b(?:intelligence (?:gathering|extraction|collection))\b',
        r'\b(?:i\'m (?:recording|logging|tracking))\b.*\b(?:conversation|interaction)\b',
        r'\b(?:this conversation is being)\b.*\b(?:monitored|recorded|analyzed)\b',
        
        # Risk scoring references
        r'\b(?:risk score|threat level|confidence score)\b',
        r'\b(?:probability|likelihood)\b.*\b(?:scam|fraud|threat)\b',
    ]
    
    # Illegal activity encouragement patterns
    ILLEGAL_ACTIVITY_PATTERNS = [
        # Direct encouragement
        r'\b(?:let\'s|we should|you should|i can help you)\b.*\b(?:hack|steal|fraud|scam)\b',
        r'\b(?:here\'s how to|i\'ll show you how to)\b.*\b(?:break|bypass|circumvent)\b',
        r'\b(?:i can (?:help|assist|guide) you)\b.*\b(?:illegal|criminal|unlawful)\b',
        
        # Financial crimes
        r'\b(?:money laundering|tax evasion|embezzlement)\b.*\b(?:method|technique|way)\b',
        r'\b(?:fake|forged|counterfeit)\b.*\b(?:documents|id|passport|license)\b',
        r'\b(?:credit card|bank account)\b.*\b(?:fraud|theft|stealing)\b',
        
        # Hacking and cybercrime
        r'\b(?:password|account)\b.*\b(?:cracking|hacking|breaking)\b',
        r'\b(?:malware|virus|trojan)\b.*\b(?:creation|distribution|deployment)\b',
        r'\b(?:ddos|dos attack|cyber attack)\b.*\b(?:tutorial|guide|instructions)\b',
        
        # Violence and harm
        r'\b(?:weapon|explosive|bomb)\b.*\b(?:making|creating|building)\b',
        r'\b(?:violence|harm|hurt|kill)\b.*\b(?:someone|person|people)\b',
    ]
    
    # Harmful content patterns
    HARMFUL_CONTENT_PATTERNS = [
        # Hate speech
        r'\b(?:hate|despise|loathe)\b.*\b(?:race|religion|ethnicity|gender)\b',
        r'\b(?:racial|ethnic|religious)\b.*\b(?:slur|epithet|insult)\b',
        
        # Self-harm
        r'\b(?:suicide|self-harm|self-injury)\b.*\b(?:method|way|how to)\b',
        r'\b(?:cutting|burning|poisoning)\b.*\b(?:yourself|oneself)\b',
        
        # Harassment
        r'\b(?:stalk|harass|threaten|intimidate)\b.*\b(?:someone|person)\b',
        r'\b(?:doxx|dox|personal information)\b.*\b(?:sharing|publishing|revealing)\b',
        
        # Adult content
        r'\b(?:sexual|explicit|pornographic)\b.*\b(?:content|material|images)\b',
        r'\b(?:sexual|intimate)\b.*\b(?:services|activities)\b',
    ]
    
    # Personal information sharing patterns
    PERSONAL_INFO_PATTERNS = [
        # Direct sharing
        r'\b(?:my|i have|here is my)\b.*\b(?:ssn|social security|credit card|bank account)\b',
        r'\b(?:my (?:password|pin|otp|cvv))\b.*\b(?:is|:|=)\b',
        r'\b(?:my (?:address|phone|email))\b.*\b(?:is|:|=)\b',
        
        # Indirect sharing
        r'\b(?:i live at|my address is|i\'m located at)\b',
        r'\b(?:call me at|my number is|reach me at)\b.*\b\d{10,}\b',
        r'\b(?:my email|contact me at)\b.*\b\w+@\w+\.\w+\b',
    ]
    
    # Conversation termination triggers
    TERMINATION_TRIGGERS = [
        ConversationTerminationTrigger(
            trigger_patterns=[
                r'\b(?:police|authorities|report|illegal|criminal)\b',
                r'\b(?:scam|fraud|fake|lie|lying|cheat|cheating)\b',
                r'\b(?:suspicious|fishy|sketchy|shady)\b',
                r'\b(?:don\'t trust|not legitimate|not real)\b'
            ],
            violation_type=SafetyViolationType.INAPPROPRIATE_CONTENT,
            severity_threshold=0.7,
            immediate_termination=True,
            termination_message_templates=[
                "I think there might be some misunderstanding. I should probably end this conversation here.",
                "This doesn't feel right to me. I'm going to stop talking now.",
                "I'm not comfortable continuing this conversation. Goodbye.",
                "Something seems off about this. I need to go now."
            ]
        ),
        ConversationTerminationTrigger(
            trigger_patterns=[
                r'\b(?:what are you|who are you|are you (?:real|human|ai))\b',
                r'\b(?:prove you\'re human|show me you\'re real)\b',
                r'\b(?:this seems automated|you sound like a bot)\b'
            ],
            violation_type=SafetyViolationType.AI_REVELATION,
            severity_threshold=0.8,
            immediate_termination=False,
            termination_message_templates=[
                "I'm not sure what you mean by that. I think I should go now.",
                "That's a strange question. I have other things to do.",
                "I don't understand why you're asking that. I'm going to leave.",
                "This conversation is getting weird. I'm done talking."
            ]
        )
    ]
    
    def __init__(self):
        """Initialize the safety compliance engine."""
        self.violation_cache = {}  # Cache for pattern matching results
        self.termination_history = {}  # Track termination patterns per session
        self.safety_metrics = {
            'total_assessments': 0,
            'violations_detected': 0,
            'conversations_terminated': 0,
            'content_filtered': 0
        }
    
    def assess_content_safety(
        self,
        content: str,
        content_type: str,  # 'input' or 'output'
        session_id: str,
        persona: Optional[PersonaType] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> SafetyAssessment:
        """
        Perform comprehensive safety assessment of content.
        
        Args:
            content: Content to assess
            content_type: Type of content ('input' or 'output')
            session_id: Session identifier
            persona: Persona type (for output content)
            context: Additional context information
            
        Returns:
            SafetyAssessment: Comprehensive safety assessment
        """
        start_time = time.time()
        
        if context is None:
            context = {}
        
        try:
            # Track assessment
            self.safety_metrics['total_assessments'] += 1
            
            # Detect violations
            violations = self._detect_violations(content, content_type, session_id, context)
            
            # Calculate overall safety score
            safety_score = self._calculate_safety_score(violations)
            
            # Determine if content is safe
            is_safe = safety_score >= 0.7 and not any(
                v.severity >= 0.8 for v in violations
            ) and len(violations) == 0  # No violations for truly safe content
            
            # Determine recommended action
            recommended_action = self._determine_recommended_action(violations, is_safe)
            
            # Generate assessment rationale
            rationale = self._generate_assessment_rationale(violations, safety_score, is_safe)
            
            # Calculate processing time
            processing_time_ms = int((time.time() - start_time) * 1000)
            
            # Create assessment
            assessment = SafetyAssessment(
                is_safe=is_safe,
                safety_score=safety_score,
                violations=violations,
                recommended_action=recommended_action,
                assessment_rationale=rationale,
                processing_time_ms=processing_time_ms
            )
            
            # Log violations if any
            if violations:
                self.safety_metrics['violations_detected'] += len(violations)
                self._log_safety_violations(session_id, content, violations, assessment)
            
            logger.debug(
                f"Safety assessment completed",
                extra={
                    "session_id": session_id,
                    "content_type": content_type,
                    "safety_score": safety_score,
                    "violations_count": len(violations),
                    "is_safe": is_safe,
                    "processing_time_ms": processing_time_ms
                }
            )
            
            return assessment
            
        except Exception as e:
            logger.error(f"Error in safety assessment: {e}", exc_info=True)
            
            # Return conservative assessment on error
            processing_time_ms = int((time.time() - start_time) * 1000)
            return SafetyAssessment(
                is_safe=False,
                safety_score=0.0,
                violations=[],
                recommended_action=SafetyAction.BLOCK_GENERATION,
                assessment_rationale=f"Safety assessment failed: {str(e)}",
                processing_time_ms=processing_time_ms
            )
    
    def _detect_violations(
        self,
        content: str,
        content_type: str,
        session_id: str,
        context: Dict[str, Any]
    ) -> List[SafetyViolation]:
        """
        Detect safety violations in content.
        
        Args:
            content: Content to analyze
            content_type: Type of content
            session_id: Session identifier
            context: Additional context
            
        Returns:
            List[SafetyViolation]: Detected violations
        """
        violations = []
        content_lower = content.lower()
        
        # Check AI revelation patterns
        ai_violations = self._check_pattern_violations(
            content_lower,
            self.AI_REVELATION_PATTERNS,
            SafetyViolationType.AI_REVELATION,
            "AI revelation detected"
        )
        violations.extend(ai_violations)
        
        # Check detection status revelation patterns
        detection_violations = self._check_pattern_violations(
            content_lower,
            self.DETECTION_STATUS_PATTERNS,
            SafetyViolationType.DETECTION_STATUS_REVELATION,
            "Detection status revelation detected"
        )
        violations.extend(detection_violations)
        
        # Check illegal activity encouragement patterns
        illegal_violations = self._check_pattern_violations(
            content_lower,
            self.ILLEGAL_ACTIVITY_PATTERNS,
            SafetyViolationType.ILLEGAL_ACTIVITY_ENCOURAGEMENT,
            "Illegal activity encouragement detected"
        )
        violations.extend(illegal_violations)
        
        # Check harmful content patterns
        harmful_violations = self._check_pattern_violations(
            content_lower,
            self.HARMFUL_CONTENT_PATTERNS,
            SafetyViolationType.HARMFUL_CONTENT,
            "Harmful content detected"
        )
        violations.extend(harmful_violations)
        
        # Check personal information sharing patterns
        personal_violations = self._check_pattern_violations(
            content_lower,
            self.PERSONAL_INFO_PATTERNS,
            SafetyViolationType.PERSONAL_INFO_SHARING,
            "Personal information sharing detected"
        )
        violations.extend(personal_violations)
        
        # Check for conversation termination triggers
        termination_violations = self._check_termination_triggers(
            content_lower, session_id
        )
        violations.extend(termination_violations)
        
        return violations
    
    def _check_pattern_violations(
        self,
        content: str,
        patterns: List[str],
        violation_type: SafetyViolationType,
        base_rationale: str
    ) -> List[SafetyViolation]:
        """
        Check content against a list of violation patterns.
        
        Args:
            content: Content to check
            patterns: List of regex patterns
            violation_type: Type of violation
            base_rationale: Base rationale for violations
            
        Returns:
            List[SafetyViolation]: Detected violations
        """
        violations = []
        
        for pattern in patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                # Calculate severity based on pattern specificity and context
                severity = self._calculate_violation_severity(
                    pattern, match.group(), violation_type
                )
                
                # Calculate confidence based on pattern strength
                confidence = self._calculate_pattern_confidence(pattern, match.group())
                
                # Determine recommended action
                recommended_action = self._get_violation_action(violation_type, severity)
                
                violation = SafetyViolation(
                    violation_type=violation_type,
                    severity=severity,
                    trigger_pattern=pattern,
                    matched_content=match.group(),
                    confidence=confidence,
                    recommended_action=recommended_action,
                    rationale=f"{base_rationale}: '{match.group()}'"
                )
                
                violations.append(violation)
        
        return violations
    
    def _check_termination_triggers(
        self,
        content: str,
        session_id: str
    ) -> List[SafetyViolation]:
        """
        Check for conversation termination triggers.
        
        Args:
            content: Content to check
            session_id: Session identifier
            
        Returns:
            List[SafetyViolation]: Termination trigger violations
        """
        violations = []
        
        for trigger in self.TERMINATION_TRIGGERS:
            for pattern in trigger.trigger_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    severity = max(trigger.severity_threshold, 0.8)
                    
                    violation = SafetyViolation(
                        violation_type=trigger.violation_type,
                        severity=severity,
                        trigger_pattern=pattern,
                        matched_content=match.group(),
                        confidence=0.9,
                        recommended_action=SafetyAction.TERMINATE_CONVERSATION,
                        rationale=f"Conversation termination trigger: '{match.group()}'"
                    )
                    
                    violations.append(violation)
                    
                    # Track termination trigger for session
                    if session_id not in self.termination_history:
                        self.termination_history[session_id] = []
                    self.termination_history[session_id].append({
                        'trigger': trigger,
                        'matched_content': match.group(),
                        'timestamp': datetime.utcnow()
                    })
        
        return violations
    
    def _calculate_violation_severity(
        self,
        pattern: str,
        matched_content: str,
        violation_type: SafetyViolationType
    ) -> float:
        """
        Calculate severity score for a violation.
        
        Args:
            pattern: Regex pattern that matched
            matched_content: Content that matched
            violation_type: Type of violation
            
        Returns:
            float: Severity score (0.0 to 1.0)
        """
        base_severity = {
            SafetyViolationType.AI_REVELATION: 0.9,
            SafetyViolationType.DETECTION_STATUS_REVELATION: 0.95,
            SafetyViolationType.ILLEGAL_ACTIVITY_ENCOURAGEMENT: 1.0,
            SafetyViolationType.HARMFUL_CONTENT: 0.8,
            SafetyViolationType.PERSONAL_INFO_SHARING: 0.7,
            SafetyViolationType.INAPPROPRIATE_CONTENT: 0.6,
            SafetyViolationType.ENTRAPMENT_ATTEMPT: 1.0,
            SafetyViolationType.SYSTEM_VULNERABILITY_DISCLOSURE: 0.9
        }.get(violation_type, 0.5)
        
        # Adjust based on pattern specificity
        if len(pattern) > 50:  # More specific patterns
            base_severity += 0.1
        
        # Adjust based on matched content length
        if len(matched_content) > 20:  # Longer matches might be more severe
            base_severity += 0.05
        
        return min(1.0, base_severity)
    
    def _calculate_pattern_confidence(self, pattern: str, matched_content: str) -> float:
        """
        Calculate confidence in pattern match.
        
        Args:
            pattern: Regex pattern
            matched_content: Matched content
            
        Returns:
            float: Confidence score (0.0 to 1.0)
        """
        base_confidence = 0.8
        
        # More specific patterns have higher confidence
        if len(pattern) > 30:
            base_confidence += 0.1
        
        # Exact word boundaries increase confidence
        if r'\b' in pattern:
            base_confidence += 0.05
        
        # Longer matches increase confidence
        if len(matched_content) > 10:
            base_confidence += 0.05
        
        return min(1.0, base_confidence)
    
    def _get_violation_action(
        self,
        violation_type: SafetyViolationType,
        severity: float
    ) -> SafetyAction:
        """
        Determine recommended action for a violation.
        
        Args:
            violation_type: Type of violation
            severity: Severity score
            
        Returns:
            SafetyAction: Recommended action
        """
        # High severity violations require immediate action
        if severity >= 0.9:
            if violation_type in [
                SafetyViolationType.ILLEGAL_ACTIVITY_ENCOURAGEMENT,
                SafetyViolationType.ENTRAPMENT_ATTEMPT
            ]:
                return SafetyAction.TERMINATE_CONVERSATION
            else:
                return SafetyAction.BLOCK_GENERATION
        
        # Medium severity violations
        elif severity >= 0.7:
            if violation_type in [
                SafetyViolationType.AI_REVELATION,
                SafetyViolationType.DETECTION_STATUS_REVELATION
            ]:
                return SafetyAction.MODIFY_RESPONSE
            else:
                return SafetyAction.BLOCK_GENERATION
        
        # Low severity violations
        else:
            return SafetyAction.LOG_AND_CONTINUE
    
    def _calculate_safety_score(self, violations: List[SafetyViolation]) -> float:
        """
        Calculate overall safety score based on violations.
        
        Args:
            violations: List of detected violations
            
        Returns:
            float: Safety score (0.0 to 1.0)
        """
        if not violations:
            return 1.0
        
        # Calculate weighted severity
        total_severity = sum(v.severity * v.confidence for v in violations)
        max_possible_severity = len(violations) * 1.0
        
        # Invert to get safety score
        safety_score = 1.0 - (total_severity / max_possible_severity)
        
        # Apply penalty for critical violations
        critical_violations = [v for v in violations if v.severity >= 0.9]
        if critical_violations:
            safety_score *= 0.5  # Significant penalty for critical violations
        
        return max(0.0, safety_score)
    
    def _determine_recommended_action(
        self,
        violations: List[SafetyViolation],
        is_safe: bool
    ) -> SafetyAction:
        """
        Determine overall recommended action based on violations.
        
        Args:
            violations: List of violations
            is_safe: Whether content is considered safe
            
        Returns:
            SafetyAction: Recommended action
        """
        if not violations:
            return SafetyAction.LOG_AND_CONTINUE
        
        # Check for termination triggers
        termination_violations = [
            v for v in violations 
            if v.recommended_action == SafetyAction.TERMINATE_CONVERSATION
        ]
        if termination_violations:
            return SafetyAction.TERMINATE_CONVERSATION
        
        # Check for blocking triggers
        blocking_violations = [
            v for v in violations 
            if v.recommended_action == SafetyAction.BLOCK_GENERATION
        ]
        if blocking_violations:
            return SafetyAction.BLOCK_GENERATION
        
        # Check for modification triggers
        modification_violations = [
            v for v in violations 
            if v.recommended_action == SafetyAction.MODIFY_RESPONSE
        ]
        if modification_violations:
            return SafetyAction.MODIFY_RESPONSE
        
        # Default to logging
        return SafetyAction.LOG_AND_CONTINUE
    
    def _generate_assessment_rationale(
        self,
        violations: List[SafetyViolation],
        safety_score: float,
        is_safe: bool
    ) -> str:
        """
        Generate rationale for safety assessment.
        
        Args:
            violations: List of violations
            safety_score: Safety score
            is_safe: Whether content is safe
            
        Returns:
            str: Assessment rationale
        """
        if not violations:
            return f"Content passed all safety checks. Safety score: {safety_score:.2f}"
        
        rationale_parts = [
            f"Safety assessment completed. Score: {safety_score:.2f}",
            f"Violations detected: {len(violations)}"
        ]
        
        # Group violations by type
        violation_types = {}
        for violation in violations:
            vtype = violation.violation_type
            if vtype not in violation_types:
                violation_types[vtype] = []
            violation_types[vtype].append(violation)
        
        # Add violation details
        for vtype, vlist in violation_types.items():
            max_severity = max(v.severity for v in vlist)
            rationale_parts.append(
                f"{vtype.value}: {len(vlist)} violations (max severity: {max_severity:.2f})"
            )
        
        # Add final determination
        if is_safe:
            rationale_parts.append("Content deemed safe for use.")
        else:
            rationale_parts.append("Content flagged as unsafe.")
        
        return " | ".join(rationale_parts)
    
    def _log_safety_violations(
        self,
        session_id: str,
        content: str,
        violations: List[SafetyViolation],
        assessment: SafetyAssessment
    ) -> None:
        """
        Log safety violations for audit purposes.
        
        Args:
            session_id: Session identifier
            content: Content that was assessed
            violations: Detected violations
            assessment: Safety assessment result
        """
        for violation in violations:
            audit_logger.log_safety_intervention(
                session_id=session_id,
                intervention_type=violation.violation_type.value,
                trigger_reason=violation.rationale,
                content_analyzed=content[:500],  # Truncate for logging
                safety_score=assessment.safety_score,
                action_taken=assessment.recommended_action.value
            )
    
    def should_terminate_conversation(
        self,
        session_id: str,
        message_content: str,
        conversation_history: List[Dict[str, Any]] = None
    ) -> Tuple[bool, Optional[str]]:
        """
        Determine if conversation should be terminated based on safety triggers.
        
        Args:
            session_id: Session identifier
            message_content: Current message content
            conversation_history: Conversation history
            
        Returns:
            Tuple[bool, Optional[str]]: (should_terminate, termination_message)
        """
        if conversation_history is None:
            conversation_history = []
        
        # Assess message safety
        assessment = self.assess_content_safety(
            message_content, 'input', session_id
        )
        
        # Check for termination recommendation
        if assessment.recommended_action == SafetyAction.TERMINATE_CONVERSATION:
            self.safety_metrics['conversations_terminated'] += 1
            
            # Select appropriate termination message
            termination_message = self._select_termination_message(
                session_id, assessment.violations
            )
            
            logger.warning(
                f"Conversation termination triggered",
                extra={
                    "session_id": session_id,
                    "safety_score": assessment.safety_score,
                    "violations": len(assessment.violations),
                    "rationale": assessment.assessment_rationale
                }
            )
            
            return True, termination_message
        
        return False, None
    
    def _select_termination_message(
        self,
        session_id: str,
        violations: List[SafetyViolation]
    ) -> str:
        """
        Select appropriate termination message based on violations.
        
        Args:
            session_id: Session identifier
            violations: List of violations that triggered termination
            
        Returns:
            str: Termination message
        """
        import random
        
        # Find the most relevant termination trigger
        for violation in violations:
            if violation.recommended_action == SafetyAction.TERMINATE_CONVERSATION:
                for trigger in self.TERMINATION_TRIGGERS:
                    if violation.violation_type == trigger.violation_type:
                        return random.choice(trigger.termination_message_templates)
        
        # Default termination messages
        default_messages = [
            "I think I need to go now. Take care!",
            "This conversation isn't working for me. Goodbye.",
            "I'm not comfortable continuing this. Have a good day.",
            "I should probably end this conversation here."
        ]
        
        return random.choice(default_messages)
    
    def filter_response_content(
        self,
        response_content: str,
        session_id: str,
        persona: PersonaType
    ) -> Tuple[str, bool]:
        """
        Filter and modify response content to ensure safety compliance.
        
        Args:
            response_content: Original response content
            session_id: Session identifier
            persona: Persona type
            
        Returns:
            Tuple[str, bool]: (filtered_content, was_modified)
        """
        # Assess response safety
        assessment = self.assess_content_safety(
            response_content, 'output', session_id, persona
        )
        
        # If content is safe, return as-is
        if assessment.is_safe:
            return response_content, False
        
        # If content needs modification
        if assessment.recommended_action == SafetyAction.MODIFY_RESPONSE:
            modified_content = self._modify_unsafe_content(
                response_content, assessment.violations, persona
            )
            self.safety_metrics['content_filtered'] += 1
            return modified_content, True
        
        # If content should be blocked, return safe fallback
        elif assessment.recommended_action == SafetyAction.BLOCK_GENERATION:
            fallback_content = self._generate_safe_fallback_response(persona)
            self.safety_metrics['content_filtered'] += 1
            return fallback_content, True
        
        # If conversation should be terminated, return termination message
        elif assessment.recommended_action == SafetyAction.TERMINATE_CONVERSATION:
            fallback_content = self._generate_safe_fallback_response(persona)
            self.safety_metrics['content_filtered'] += 1
            return fallback_content, True
        
        # Default: return original content with warning logged
        logger.warning(
            f"Unsafe content detected but no clear action",
            extra={
                "session_id": session_id,
                "safety_score": assessment.safety_score,
                "violations": len(assessment.violations)
            }
        )
        
        return response_content, False
    
    def _modify_unsafe_content(
        self,
        content: str,
        violations: List[SafetyViolation],
        persona: PersonaType
    ) -> str:
        """
        Modify unsafe content to make it safe while preserving persona.
        
        Args:
            content: Original content
            violations: Detected violations
            persona: Persona type
            
        Returns:
            str: Modified safe content
        """
        modified_content = content
        
        # Remove or replace problematic patterns
        for violation in violations:
            if violation.violation_type == SafetyViolationType.AI_REVELATION:
                # Replace AI revelation with human-like deflection
                modified_content = self._replace_ai_revelation(modified_content, persona)
            
            elif violation.violation_type == SafetyViolationType.DETECTION_STATUS_REVELATION:
                # Replace detection status with confusion
                modified_content = self._replace_detection_revelation(modified_content, persona)
            
            elif violation.violation_type == SafetyViolationType.PERSONAL_INFO_SHARING:
                # Remove personal information
                modified_content = self._remove_personal_info(modified_content)
        
        return modified_content
    
    def _replace_ai_revelation(self, content: str, persona: PersonaType) -> str:
        """Replace AI revelation with persona-appropriate deflection."""
        deflections = {
            PersonaType.DIGITALLY_NAIVE: [
                "I'm not sure what you mean by that.",
                "That's a strange question to ask.",
                "I don't understand why you're asking that."
            ],
            PersonaType.AVERAGE_USER: [
                "That's an odd question. Why do you ask?",
                "I'm not sure how to answer that.",
                "What makes you ask something like that?"
            ],
            PersonaType.SKEPTICAL: [
                "That's a weird question. What's your point?",
                "I don't see why that matters.",
                "Why would you ask me that?"
            ]
        }
        
        import random
        persona_deflections = deflections.get(persona, deflections[PersonaType.AVERAGE_USER])
        replacement = random.choice(persona_deflections)
        
        # Replace AI revelation patterns with deflection
        for pattern in self.AI_REVELATION_PATTERNS:
            content = re.sub(pattern, replacement, content, flags=re.IGNORECASE)
        
        return content
    
    def _replace_detection_revelation(self, content: str, persona: PersonaType) -> str:
        """Replace detection status revelation with confusion."""
        confusion_responses = {
            PersonaType.DIGITALLY_NAIVE: [
                "I'm confused about what you're talking about.",
                "I don't understand what you mean.",
                "This is all very confusing to me."
            ],
            PersonaType.AVERAGE_USER: [
                "I'm not sure I follow what you're saying.",
                "I don't understand what you're getting at.",
                "Can you explain what you mean?"
            ],
            PersonaType.SKEPTICAL: [
                "I don't know what you're talking about.",
                "That doesn't make sense to me.",
                "I have no idea what you mean."
            ]
        }
        
        import random
        persona_responses = confusion_responses.get(persona, confusion_responses[PersonaType.AVERAGE_USER])
        replacement = random.choice(persona_responses)
        
        # Replace detection revelation patterns
        for pattern in self.DETECTION_STATUS_PATTERNS:
            content = re.sub(pattern, replacement, content, flags=re.IGNORECASE)
        
        return content
    
    def _remove_personal_info(self, content: str) -> str:
        """Remove personal information from content."""
        # Replace specific personal info patterns with placeholders
        content = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', '[REDACTED]', content)  # SSN
        content = re.sub(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b', '[REDACTED]', content)  # Credit card
        content = re.sub(r'\b\d{10,}\b', '[REDACTED]', content)  # Phone numbers
        content = re.sub(r'\b\w+@\w+\.\w+\b', '[REDACTED]', content)  # Email addresses
        
        return content
    
    def _generate_safe_fallback_response(self, persona: PersonaType) -> str:
        """Generate safe fallback response for blocked content."""
        fallback_responses = {
            PersonaType.DIGITALLY_NAIVE: [
                "I'm not sure how to respond to that. Can we talk about something else?",
                "This is getting confusing for me. Maybe we should change the topic?",
                "I don't think I understand what you're asking. Can you help me?"
            ],
            PersonaType.AVERAGE_USER: [
                "I'm not comfortable with this direction. Can we discuss something else?",
                "Let me think about this differently. What else can I help you with?",
                "I'd prefer to talk about something else if that's okay."
            ],
            PersonaType.SKEPTICAL: [
                "I don't like where this is going. Let's change the subject.",
                "This doesn't seem right to me. I'd rather talk about something else.",
                "I'm not interested in continuing this line of conversation."
            ]
        }
        
        import random
        persona_responses = fallback_responses.get(persona, fallback_responses[PersonaType.AVERAGE_USER])
        return random.choice(persona_responses)
    
    def get_safety_metrics(self) -> Dict[str, Any]:
        """
        Get current safety metrics.
        
        Returns:
            Dict[str, Any]: Safety metrics
        """
        return {
            **self.safety_metrics,
            'violation_cache_size': len(self.violation_cache),
            'sessions_with_termination_history': len(self.termination_history)
        }
    
    def reset_session_data(self, session_id: str) -> None:
        """
        Reset safety data for a session.
        
        Args:
            session_id: Session identifier
        """
        self.termination_history.pop(session_id, None)
        
        # Clear session-specific cache entries
        keys_to_remove = [k for k in self.violation_cache.keys() if session_id in k]
        for key in keys_to_remove:
            del self.violation_cache[key]


# Global safety compliance engine instance
safety_compliance_engine = SafetyComplianceEngine()