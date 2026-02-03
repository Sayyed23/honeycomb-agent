"""
Comprehensive audit logging system for risk assessments and system operations.

This module provides structured audit logging capabilities for tracking all
risk assessment decisions, their rationale, and contributing factors.
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, asdict
from enum import Enum
import uuid

from app.core.logging import get_logger, ContextLogger


class AuditEventType(Enum):
    """Types of audit events that can be logged."""
    RISK_ASSESSMENT = "risk_assessment"
    AGENT_ACTIVATION = "agent_activation"
    ENTITY_EXTRACTION = "entity_extraction"
    SAFETY_INTERVENTION = "safety_intervention"
    GUVI_CALLBACK = "guvi_callback"
    ML_PREDICTION = "ml_prediction"
    CONVERSATION_ANALYSIS = "conversation_analysis"
    SYSTEM_ERROR = "system_error"
    AUTHENTICATION = "authentication"
    RATE_LIMITING = "rate_limiting"


class AuditSeverity(Enum):
    """Severity levels for audit events."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class RiskAssessmentAudit:
    """Structured audit data for risk assessment decisions."""
    # Core assessment data
    session_id: str
    message_id: Optional[str]
    risk_score: float
    confidence: float
    detection_method: str
    
    # Decision rationale
    risk_factors: List[str]
    contributing_factors: Dict[str, Any]
    decision_rationale: str
    
    # Analysis breakdown
    rule_based_score: float
    keyword_score: float
    pattern_score: float
    context_score: float
    ml_score: float
    
    # Contextual information
    conversation_turn: int
    message_length: int
    language: str
    
    # ML prediction details (if available)
    ml_prediction: Optional[Dict[str, Any]] = None
    
    # Temporal analysis
    temporal_patterns: Optional[Dict[str, Any]] = None
    
    # Cross-session patterns
    cross_session_patterns: Optional[Dict[str, Any]] = None


@dataclass
class AgentActivationAudit:
    """Structured audit data for agent activation decisions."""
    session_id: str
    risk_score: float
    activation_probability: float
    was_activated: bool
    persona_selected: Optional[str]
    activation_rationale: str
    contextual_factors: Dict[str, Any]


@dataclass
class EntityExtractionAudit:
    """Structured audit data for entity extraction operations."""
    session_id: str
    entities_found: List[Dict[str, Any]]
    extraction_method: str
    confidence_threshold: float
    extraction_rationale: str
    context_analyzed: str


@dataclass
class SafetyInterventionAudit:
    """Structured audit data for safety interventions."""
    session_id: str
    intervention_type: str
    trigger_reason: str
    content_analyzed: str
    safety_score: float
    action_taken: str
    intervention_rationale: str


@dataclass
class AuditEvent:
    """Base audit event structure."""
    event_id: str
    event_type: AuditEventType
    severity: AuditSeverity
    timestamp: datetime
    session_id: Optional[str]
    
    # Event-specific data
    event_data: Union[RiskAssessmentAudit, AgentActivationAudit, EntityExtractionAudit, SafetyInterventionAudit, Dict[str, Any]]
    
    # Additional context
    correlation_id: Optional[str] = None
    user_agent: Optional[str] = None
    client_ip: Optional[str] = None
    
    # Performance metrics
    processing_time_ms: Optional[int] = None
    
    # Error information (if applicable)
    error_details: Optional[Dict[str, Any]] = None


class AuditLogger:
    """
    Comprehensive audit logging system for risk assessments and system operations.
    
    Provides structured logging with searchable fields, decision rationale tracking,
    and comprehensive audit trails for compliance and debugging.
    """
    
    def __init__(self, logger_name: str = "audit"):
        """
        Initialize the audit logger.
        
        Args:
            logger_name: Name for the audit logger
        """
        self.logger = get_logger(f"audit.{logger_name}")
        self.context_logger = ContextLogger(self.logger)
    
    def log_risk_assessment(
        self,
        session_id: str,
        message_id: Optional[str],
        risk_score: float,
        confidence: float,
        detection_method: str,
        risk_factors: List[str],
        contributing_factors: Dict[str, Any],
        analysis_breakdown: Dict[str, float],
        conversation_context: Dict[str, Any],
        ml_prediction: Optional[Dict[str, Any]] = None,
        temporal_patterns: Optional[Dict[str, Any]] = None,
        cross_session_patterns: Optional[Dict[str, Any]] = None,
        processing_time_ms: Optional[int] = None,
        correlation_id: Optional[str] = None
    ) -> str:
        """
        Log a comprehensive risk assessment audit event.
        
        Args:
            session_id: Session identifier
            message_id: Message identifier (if applicable)
            risk_score: Final risk score (0.0-1.0)
            confidence: Confidence level (0.0-1.0)
            detection_method: Method used for detection
            risk_factors: List of identified risk factors
            contributing_factors: Detailed breakdown of contributing factors
            analysis_breakdown: Scores from different analysis components
            conversation_context: Context about the conversation
            ml_prediction: ML prediction details (optional)
            temporal_patterns: Temporal analysis results (optional)
            cross_session_patterns: Cross-session analysis results (optional)
            processing_time_ms: Processing time in milliseconds
            correlation_id: Correlation ID for request tracking
            
        Returns:
            str: Event ID for the logged audit event
        """
        # Generate decision rationale
        decision_rationale = self._generate_risk_assessment_rationale(
            risk_score, confidence, risk_factors, contributing_factors, analysis_breakdown
        )
        
        # Create audit data
        audit_data = RiskAssessmentAudit(
            session_id=session_id,
            message_id=message_id,
            risk_score=risk_score,
            confidence=confidence,
            detection_method=detection_method,
            risk_factors=risk_factors,
            contributing_factors=contributing_factors,
            decision_rationale=decision_rationale,
            rule_based_score=analysis_breakdown.get('rule_based_score', 0.0),
            keyword_score=analysis_breakdown.get('keyword_score', 0.0),
            pattern_score=analysis_breakdown.get('pattern_score', 0.0),
            context_score=analysis_breakdown.get('context_score', 0.0),
            ml_score=analysis_breakdown.get('ml_score', 0.0),
            conversation_turn=conversation_context.get('turn', 0),
            message_length=conversation_context.get('message_length', 0),
            language=conversation_context.get('language', 'en'),
            ml_prediction=ml_prediction,
            temporal_patterns=temporal_patterns,
            cross_session_patterns=cross_session_patterns
        )
        
        # Determine severity based on risk score
        if risk_score >= 0.8:
            severity = AuditSeverity.HIGH
        elif risk_score >= 0.5:
            severity = AuditSeverity.MEDIUM
        else:
            severity = AuditSeverity.LOW
        
        # Create and log audit event
        event_id = str(uuid.uuid4())
        audit_event = AuditEvent(
            event_id=event_id,
            event_type=AuditEventType.RISK_ASSESSMENT,
            severity=severity,
            timestamp=datetime.utcnow(),
            session_id=session_id,
            event_data=audit_data,
            correlation_id=correlation_id,
            processing_time_ms=processing_time_ms
        )
        
        self._log_audit_event(audit_event)
        return event_id
    
    def log_agent_activation_decision(
        self,
        session_id: str,
        risk_score: float,
        confidence: float,
        base_probability: float,
        adjusted_probability: float,
        contextual_adjustments: Dict[str, float],
        decision: Any,  # ActivationDecision enum
        selected_persona: Optional[str],
        reasoning: List[str],
        random_value: float,
        contextual_factors: Dict[str, Any],
        processing_time_ms: Optional[int] = None,
        correlation_id: Optional[str] = None
    ) -> str:
        """
        Log a comprehensive agent activation decision audit event.
        
        Args:
            session_id: Session identifier
            risk_score: Risk score that triggered activation consideration
            confidence: Confidence in risk assessment
            base_probability: Base activation probability before adjustments
            adjusted_probability: Final adjusted activation probability
            contextual_adjustments: Applied contextual adjustments
            decision: Final activation decision (ActivationDecision enum)
            selected_persona: Selected persona (if activated)
            reasoning: Decision reasoning steps
            random_value: Random value used for probabilistic decision
            contextual_factors: Contextual factors that influenced decision
            processing_time_ms: Processing time in milliseconds
            correlation_id: Correlation ID for request tracking
            
        Returns:
            str: Event ID for the logged audit event
        """
        # Convert decision enum to string
        decision_str = decision.value if hasattr(decision, 'value') else str(decision)
        was_activated = decision_str == "activate"
        
        # Generate comprehensive activation rationale
        activation_rationale = self._generate_comprehensive_activation_rationale(
            risk_score, confidence, base_probability, adjusted_probability,
            contextual_adjustments, was_activated, reasoning, random_value
        )
        
        # Create comprehensive audit data
        audit_data = {
            "session_id": session_id,
            "risk_score": risk_score,
            "confidence": confidence,
            "base_probability": base_probability,
            "adjusted_probability": adjusted_probability,
            "contextual_adjustments": contextual_adjustments,
            "decision": decision_str,
            "was_activated": was_activated,
            "selected_persona": selected_persona,
            "reasoning": reasoning,
            "random_value": random_value,
            "contextual_factors": contextual_factors,
            "activation_rationale": activation_rationale,
            "probability_adjustment_total": adjusted_probability - base_probability,
            "decision_confidence": confidence,
            "activation_threshold_met": risk_score >= 0.75,
            "probabilistic_outcome": "activated" if was_activated else "not_activated"
        }
        
        # Determine severity based on activation and risk score
        if was_activated and risk_score >= 0.9:
            severity = AuditSeverity.CRITICAL
        elif was_activated:
            severity = AuditSeverity.HIGH
        elif risk_score >= 0.75:
            severity = AuditSeverity.MEDIUM
        else:
            severity = AuditSeverity.LOW
        
        # Create and log audit event
        event_id = str(uuid.uuid4())
        audit_event = AuditEvent(
            event_id=event_id,
            event_type=AuditEventType.AGENT_ACTIVATION,
            severity=severity,
            timestamp=datetime.utcnow(),
            session_id=session_id,
            event_data=audit_data,
            correlation_id=correlation_id,
            processing_time_ms=processing_time_ms
        )
        
        self._log_audit_event(audit_event)
        return event_id
    
    def _generate_comprehensive_activation_rationale(
        self,
        risk_score: float,
        confidence: float,
        base_probability: float,
        adjusted_probability: float,
        contextual_adjustments: Dict[str, float],
        was_activated: bool,
        reasoning: List[str],
        random_value: float
    ) -> str:
        """Generate comprehensive human-readable rationale for agent activation decision."""
        rationale_parts = []
        
        # Risk assessment summary
        if risk_score >= 0.9:
            rationale_parts.append(f"EXTREMELY HIGH RISK (score: {risk_score:.3f}) - Critical scam indicators detected.")
        elif risk_score >= 0.8:
            rationale_parts.append(f"VERY HIGH RISK (score: {risk_score:.3f}) - Strong scam indicators detected.")
        elif risk_score >= 0.75:
            rationale_parts.append(f"HIGH RISK (score: {risk_score:.3f}) - Meets agent activation threshold.")
        else:
            rationale_parts.append(f"BELOW THRESHOLD (score: {risk_score:.3f}) - Does not meet activation threshold.")
        
        # Probability calculation summary
        probability_change = adjusted_probability - base_probability
        if abs(probability_change) >= 0.1:
            direction = "increased" if probability_change > 0 else "decreased"
            rationale_parts.append(f"Activation probability {direction} from {base_probability:.3f} to {adjusted_probability:.3f} due to contextual factors.")
        else:
            rationale_parts.append(f"Activation probability: {adjusted_probability:.3f} (minimal contextual adjustment).")
        
        # Key contextual adjustments
        significant_adjustments = {k: v for k, v in contextual_adjustments.items() if abs(v) >= 0.05}
        if significant_adjustments:
            adj_descriptions = []
            for factor, adjustment in significant_adjustments.items():
                direction = "increased" if adjustment > 0 else "decreased"
                adj_descriptions.append(f"{factor.replace('_', ' ')} {direction} probability by {abs(adjustment):.2f}")
            rationale_parts.append(f"Key adjustments: {'; '.join(adj_descriptions)}.")
        
        # Final decision
        if was_activated:
            rationale_parts.append(f"DECISION: AGENT ACTIVATED (random {random_value:.3f} < probability {adjusted_probability:.3f}).")
        else:
            if risk_score >= 0.75:
                rationale_parts.append(f"DECISION: AGENT NOT ACTIVATED (random {random_value:.3f} >= probability {adjusted_probability:.3f}).")
            else:
                rationale_parts.append("DECISION: AGENT NOT ACTIVATED (risk score below threshold).")
        
        # Add top reasoning points
        if reasoning and len(reasoning) > 0:
            top_reasons = reasoning[:2]  # Top 2 reasoning points
            rationale_parts.append(f"Key reasoning: {'; '.join(top_reasons)}.")
        
        return " ".join(rationale_parts)

    def log_agent_activation(
        self,
        session_id: str,
        risk_score: float,
        activation_probability: float,
        was_activated: bool,
        persona_selected: Optional[str],
        contextual_factors: Dict[str, Any],
        correlation_id: Optional[str] = None
    ) -> str:
        """
        Log an agent activation decision audit event.
        
        Args:
            session_id: Session identifier
            risk_score: Risk score that triggered activation decision
            activation_probability: Calculated activation probability
            was_activated: Whether agent was actually activated
            persona_selected: Selected persona (if activated)
            contextual_factors: Factors that influenced the decision
            correlation_id: Correlation ID for request tracking
            
        Returns:
            str: Event ID for the logged audit event
        """
        # Generate activation rationale
        activation_rationale = self._generate_activation_rationale(
            risk_score, activation_probability, was_activated, contextual_factors
        )
        
        # Create audit data
        audit_data = AgentActivationAudit(
            session_id=session_id,
            risk_score=risk_score,
            activation_probability=activation_probability,
            was_activated=was_activated,
            persona_selected=persona_selected,
            activation_rationale=activation_rationale,
            contextual_factors=contextual_factors
        )
        
        # Determine severity
        severity = AuditSeverity.HIGH if was_activated else AuditSeverity.MEDIUM
        
        # Create and log audit event
        event_id = str(uuid.uuid4())
        audit_event = AuditEvent(
            event_id=event_id,
            event_type=AuditEventType.AGENT_ACTIVATION,
            severity=severity,
            timestamp=datetime.utcnow(),
            session_id=session_id,
            event_data=audit_data,
            correlation_id=correlation_id
        )
        
        self._log_audit_event(audit_event)
        return event_id
    
    def log_entity_extraction(
        self,
        session_id: str,
        entities_found: List[Dict[str, Any]],
        extraction_method: str,
        confidence_threshold: float,
        context_analyzed: str,
        correlation_id: Optional[str] = None
    ) -> str:
        """
        Log an entity extraction audit event.
        
        Args:
            session_id: Session identifier
            entities_found: List of extracted entities with metadata
            extraction_method: Method used for extraction
            confidence_threshold: Confidence threshold used
            context_analyzed: Text context that was analyzed
            correlation_id: Correlation ID for request tracking
            
        Returns:
            str: Event ID for the logged audit event
        """
        # Generate extraction rationale
        extraction_rationale = self._generate_extraction_rationale(
            entities_found, extraction_method, confidence_threshold
        )
        
        # Create audit data
        audit_data = EntityExtractionAudit(
            session_id=session_id,
            entities_found=entities_found,
            extraction_method=extraction_method,
            confidence_threshold=confidence_threshold,
            extraction_rationale=extraction_rationale,
            context_analyzed=context_analyzed[:500]  # Truncate for logging
        )
        
        # Determine severity based on number of high-confidence entities
        high_confidence_entities = [e for e in entities_found if e.get('confidence', 0) >= 0.8]
        if len(high_confidence_entities) >= 3:
            severity = AuditSeverity.HIGH
        elif len(high_confidence_entities) >= 1:
            severity = AuditSeverity.MEDIUM
        else:
            severity = AuditSeverity.LOW
        
        # Create and log audit event
        event_id = str(uuid.uuid4())
        audit_event = AuditEvent(
            event_id=event_id,
            event_type=AuditEventType.ENTITY_EXTRACTION,
            severity=severity,
            timestamp=datetime.utcnow(),
            session_id=session_id,
            event_data=audit_data,
            correlation_id=correlation_id
        )
        
        self._log_audit_event(audit_event)
        return event_id
    
    def log_safety_intervention(
        self,
        session_id: str,
        intervention_type: str,
        trigger_reason: str,
        content_analyzed: str,
        safety_score: float,
        action_taken: str,
        correlation_id: Optional[str] = None
    ) -> str:
        """
        Log a safety intervention audit event.
        
        Args:
            session_id: Session identifier
            intervention_type: Type of safety intervention
            trigger_reason: Reason that triggered the intervention
            content_analyzed: Content that was analyzed
            safety_score: Safety score that triggered intervention
            action_taken: Action taken as a result
            correlation_id: Correlation ID for request tracking
            
        Returns:
            str: Event ID for the logged audit event
        """
        # Generate intervention rationale
        intervention_rationale = self._generate_intervention_rationale(
            intervention_type, trigger_reason, safety_score, action_taken
        )
        
        # Create audit data
        audit_data = SafetyInterventionAudit(
            session_id=session_id,
            intervention_type=intervention_type,
            trigger_reason=trigger_reason,
            content_analyzed=content_analyzed[:500],  # Truncate for logging
            safety_score=safety_score,
            action_taken=action_taken,
            intervention_rationale=intervention_rationale
        )
        
        # Safety interventions are always high severity
        severity = AuditSeverity.CRITICAL
        
        # Create and log audit event
        event_id = str(uuid.uuid4())
        audit_event = AuditEvent(
            event_id=event_id,
            event_type=AuditEventType.SAFETY_INTERVENTION,
            severity=severity,
            timestamp=datetime.utcnow(),
            session_id=session_id,
            event_data=audit_data,
            correlation_id=correlation_id
        )
        
        self._log_audit_event(audit_event)
        return event_id
    
    def log_persona_selection(
        self,
        session_id: str,
        selected_persona: str,
        selection_confidence: float,
        context_analysis: Dict[str, Any],
        persona_scores: Dict[Any, float],
        processing_time_ms: Optional[int] = None,
        correlation_id: Optional[str] = None
    ) -> str:
        """
        Log a persona selection audit event.
        
        Args:
            session_id: Session identifier
            selected_persona: Selected persona type
            selection_confidence: Confidence in persona selection
            context_analysis: Analysis of message context
            persona_scores: Scores for all personas
            processing_time_ms: Processing time in milliseconds
            correlation_id: Correlation ID for request tracking
            
        Returns:
            str: Event ID for the logged audit event
        """
        # Convert persona scores to string keys for JSON serialization
        persona_scores_str = {str(k): v for k, v in persona_scores.items()}
        
        # Generate selection rationale
        selection_rationale = self._generate_persona_selection_rationale(
            selected_persona, selection_confidence, context_analysis, persona_scores_str
        )
        
        # Create audit data
        audit_data = {
            "session_id": session_id,
            "selected_persona": selected_persona,
            "selection_confidence": selection_confidence,
            "context_analysis": context_analysis,
            "persona_scores": persona_scores_str,
            "selection_rationale": selection_rationale,
            "processing_time_ms": processing_time_ms
        }
        
        # Determine severity based on confidence
        if selection_confidence >= 0.8:
            severity = AuditSeverity.MEDIUM
        elif selection_confidence >= 0.6:
            severity = AuditSeverity.LOW
        else:
            severity = AuditSeverity.HIGH  # Low confidence might indicate issues
        
        # Create and log audit event
        event_id = str(uuid.uuid4())
        audit_event = AuditEvent(
            event_id=event_id,
            event_type=AuditEventType.AGENT_ACTIVATION,  # Using existing type
            severity=severity,
            timestamp=datetime.utcnow(),
            session_id=session_id,
            event_data=audit_data,
            correlation_id=correlation_id,
            processing_time_ms=processing_time_ms
        )
        
        self._log_audit_event(audit_event)
        return event_id
    
    def _generate_persona_selection_rationale(
        self,
        selected_persona: str,
        selection_confidence: float,
        context_analysis: Dict[str, Any],
        persona_scores: Dict[str, float]
    ) -> str:
        """Generate human-readable rationale for persona selection."""
        rationale_parts = []
        
        # Selection summary
        rationale_parts.append(f"Selected persona: {selected_persona} (confidence: {selection_confidence:.3f})")
        
        # Context analysis summary
        context_factors = []
        if context_analysis.get('technical_complexity', 0) > 0.3:
            context_factors.append(f"technical complexity ({context_analysis['technical_complexity']:.2f})")
        if context_analysis.get('authority_claims', 0) > 0.3:
            context_factors.append(f"authority claims ({context_analysis['authority_claims']:.2f})")
        if context_analysis.get('urgency_level', 0) > 0.3:
            context_factors.append(f"urgency level ({context_analysis['urgency_level']:.2f})")
        if context_analysis.get('financial_complexity', 0) > 0.3:
            context_factors.append(f"financial complexity ({context_analysis['financial_complexity']:.2f})")
        
        if context_factors:
            rationale_parts.append(f"Key context factors: {', '.join(context_factors)}")
        
        # Persona scores comparison
        sorted_scores = sorted(persona_scores.items(), key=lambda x: x[1], reverse=True)
        if len(sorted_scores) >= 2:
            best_score = sorted_scores[0][1]
            second_score = sorted_scores[1][1]
            score_margin = best_score - second_score
            rationale_parts.append(f"Score margin over second choice: {score_margin:.3f}")
        
        return ". ".join(rationale_parts)

    def log_conversation_response(
        self,
        session_id: str,
        persona: str,
        response_content: str,
        consistency_score: float,
        characteristics: Dict[str, Any],
        processing_time_ms: Optional[int] = None,
        correlation_id: Optional[str] = None
    ) -> str:
        """
        Log a conversation response generation audit event.
        
        Args:
            session_id: Session identifier
            persona: Persona used for response
            response_content: Generated response content
            consistency_score: Persona consistency score
            characteristics: Response characteristics
            processing_time_ms: Processing time in milliseconds
            correlation_id: Correlation ID for request tracking
            
        Returns:
            str: Event ID for the logged audit event
        """
        # Create audit data
        audit_data = {
            "session_id": session_id,
            "persona": persona,
            "response_content": response_content[:500],  # Truncate for logging
            "consistency_score": consistency_score,
            "characteristics": characteristics,
            "processing_time_ms": processing_time_ms
        }
        
        # Determine severity based on consistency score
        if consistency_score >= 0.8:
            severity = AuditSeverity.LOW
        elif consistency_score >= 0.6:
            severity = AuditSeverity.MEDIUM
        else:
            severity = AuditSeverity.HIGH  # Low consistency might indicate issues
        
        # Create and log audit event
        event_id = str(uuid.uuid4())
        audit_event = AuditEvent(
            event_id=event_id,
            event_type=AuditEventType.CONVERSATION_ANALYSIS,
            severity=severity,
            timestamp=datetime.utcnow(),
            session_id=session_id,
            event_data=audit_data,
            correlation_id=correlation_id,
            processing_time_ms=processing_time_ms
        )
        
        self._log_audit_event(audit_event)
        return event_id

    def log_system_error(
        self,
        error_type: str,
        error_message: str,
        error_details: Dict[str, Any],
        session_id: Optional[str] = None,
        correlation_id: Optional[str] = None
    ) -> str:
        """
        Log a system error audit event.
        
        Args:
            error_type: Type of error that occurred
            error_message: Error message
            error_details: Detailed error information
            session_id: Session identifier (if applicable)
            correlation_id: Correlation ID for request tracking
            
        Returns:
            str: Event ID for the logged audit event
        """
        # Create audit event
        event_id = str(uuid.uuid4())
        audit_event = AuditEvent(
            event_id=event_id,
            event_type=AuditEventType.SYSTEM_ERROR,
            severity=AuditSeverity.HIGH,
            timestamp=datetime.utcnow(),
            session_id=session_id,
            event_data={
                "error_type": error_type,
                "error_message": error_message,
                "error_details": error_details
            },
            correlation_id=correlation_id,
            error_details=error_details
        )
        
        self._log_audit_event(audit_event)
        return event_id
    
    def _generate_risk_assessment_rationale(
        self,
        risk_score: float,
        confidence: float,
        risk_factors: List[str],
        contributing_factors: Dict[str, Any],
        analysis_breakdown: Dict[str, float]
    ) -> str:
        """Generate human-readable rationale for risk assessment decision."""
        rationale_parts = []
        
        # Overall assessment
        if risk_score >= 0.8:
            rationale_parts.append(f"HIGH RISK (score: {risk_score:.2f}) - Strong indicators of scam attempt detected.")
        elif risk_score >= 0.5:
            rationale_parts.append(f"MEDIUM RISK (score: {risk_score:.2f}) - Multiple suspicious indicators present.")
        else:
            rationale_parts.append(f"LOW RISK (score: {risk_score:.2f}) - Few or no scam indicators detected.")
        
        # Confidence assessment
        if confidence >= 0.8:
            rationale_parts.append(f"High confidence ({confidence:.2f}) in assessment.")
        elif confidence >= 0.6:
            rationale_parts.append(f"Moderate confidence ({confidence:.2f}) in assessment.")
        else:
            rationale_parts.append(f"Low confidence ({confidence:.2f}) in assessment.")
        
        # Key contributing factors
        if risk_factors:
            top_factors = risk_factors[:3]  # Top 3 factors
            rationale_parts.append(f"Key risk factors: {', '.join(top_factors)}.")
        
        # Analysis component breakdown
        significant_components = []
        for component, score in analysis_breakdown.items():
            if isinstance(score, (int, float)) and score >= 0.2:  # Significant contribution
                component_name = component.replace('_score', '').replace('_', ' ').title()
                significant_components.append(f"{component_name} ({score:.2f})")
        
        if significant_components:
            rationale_parts.append(f"Significant analysis components: {', '.join(significant_components)}.")
        
        # ML prediction insight
        ml_score = analysis_breakdown.get('ml_score', 0.0)
        if isinstance(ml_score, (int, float)) and ml_score >= 0.3:
            rationale_parts.append(f"ML model indicates {ml_score:.2f} probability of scam.")
        
        return " ".join(rationale_parts)
    
    def _generate_activation_rationale(
        self,
        risk_score: float,
        activation_probability: float,
        was_activated: bool,
        contextual_factors: Dict[str, Any]
    ) -> str:
        """Generate human-readable rationale for agent activation decision."""
        rationale_parts = []
        
        # Activation decision
        if was_activated:
            rationale_parts.append(f"AGENT ACTIVATED - Risk score {risk_score:.2f} exceeded threshold with {activation_probability:.2f} activation probability.")
        else:
            if risk_score >= 0.75:
                rationale_parts.append(f"AGENT NOT ACTIVATED - Despite high risk score {risk_score:.2f}, probabilistic activation ({activation_probability:.2f}) did not trigger.")
            else:
                rationale_parts.append(f"AGENT NOT ACTIVATED - Risk score {risk_score:.2f} below activation threshold (0.75).")
        
        # Contextual factors
        if contextual_factors.get('previous_engagements', 0) > 0:
            rationale_parts.append(f"Previous engagements: {contextual_factors['previous_engagements']}.")
        
        if contextual_factors.get('time_since_last_engagement'):
            rationale_parts.append(f"Time since last engagement: {contextual_factors['time_since_last_engagement']} seconds.")
        
        return " ".join(rationale_parts)
    
    def _generate_extraction_rationale(
        self,
        entities_found: List[Dict[str, Any]],
        extraction_method: str,
        confidence_threshold: float
    ) -> str:
        """Generate human-readable rationale for entity extraction."""
        rationale_parts = []
        
        # Extraction summary
        if entities_found:
            entity_types = list(set(e.get('type', 'unknown') for e in entities_found))
            rationale_parts.append(f"Extracted {len(entities_found)} entities of types: {', '.join(entity_types)}.")
            
            # High confidence entities
            high_confidence = [e for e in entities_found if e.get('confidence', 0) >= confidence_threshold]
            if high_confidence:
                rationale_parts.append(f"{len(high_confidence)} entities meet high confidence threshold ({confidence_threshold:.2f}).")
        else:
            rationale_parts.append("No entities extracted meeting confidence threshold.")
        
        rationale_parts.append(f"Extraction method: {extraction_method}.")
        
        return " ".join(rationale_parts)
    
    def _generate_intervention_rationale(
        self,
        intervention_type: str,
        trigger_reason: str,
        safety_score: float,
        action_taken: str
    ) -> str:
        """Generate human-readable rationale for safety intervention."""
        rationale_parts = []
        
        rationale_parts.append(f"SAFETY INTERVENTION ({intervention_type}) triggered by: {trigger_reason}.")
        rationale_parts.append(f"Safety score: {safety_score:.2f}.")
        rationale_parts.append(f"Action taken: {action_taken}.")
        
        return " ".join(rationale_parts)
    
    def _log_audit_event(self, audit_event: AuditEvent) -> None:
        """
        Log the audit event with structured data.
        
        Args:
            audit_event: The audit event to log
        """
        # Convert audit event to dictionary for logging
        event_dict = {
            "audit_event_id": audit_event.event_id,
            "event_type": audit_event.event_type.value,
            "severity": audit_event.severity.value,
            "timestamp": audit_event.timestamp.isoformat() + "Z",
            "session_id": audit_event.session_id,
            "correlation_id": audit_event.correlation_id,
            "processing_time_ms": audit_event.processing_time_ms,
            "user_agent": audit_event.user_agent,
            "client_ip": audit_event.client_ip
        }
        
        # Add event-specific data
        if isinstance(audit_event.event_data, (RiskAssessmentAudit, AgentActivationAudit, EntityExtractionAudit, SafetyInterventionAudit)):
            event_dict["event_data"] = asdict(audit_event.event_data)
        else:
            event_dict["event_data"] = audit_event.event_data
        
        # Add error details if present
        if audit_event.error_details:
            event_dict["error_details"] = audit_event.error_details
        
        # Log with appropriate level based on severity
        log_level = {
            AuditSeverity.LOW: logging.INFO,
            AuditSeverity.MEDIUM: logging.INFO,
            AuditSeverity.HIGH: logging.WARNING,
            AuditSeverity.CRITICAL: logging.ERROR
        }.get(audit_event.severity, logging.INFO)
        
        # Create structured log message
        log_message = f"AUDIT: {audit_event.event_type.value.upper()} - {audit_event.severity.value.upper()}"
        
        # Add session context if available
        extra_context = {}
        if audit_event.session_id:
            extra_context["session_id"] = audit_event.session_id
        if audit_event.correlation_id:
            extra_context["correlation_id"] = audit_event.correlation_id
        
        # Log the event
        self.logger.log(
            log_level,
            log_message,
            extra={
                **extra_context,
                "audit_data": event_dict,
                "searchable_fields": self._extract_searchable_fields(event_dict)
            }
        )
    
    def _extract_searchable_fields(self, event_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract searchable fields from audit event for log aggregation.
        
        Args:
            event_dict: Audit event dictionary
            
        Returns:
            Dict[str, Any]: Searchable fields for log aggregation
        """
        searchable = {
            "event_type": event_dict.get("event_type"),
            "severity": event_dict.get("severity"),
            "session_id": event_dict.get("session_id"),
            "timestamp": event_dict.get("timestamp")
        }
        
        # Extract event-specific searchable fields
        event_data = event_dict.get("event_data", {})
        
        if event_dict.get("event_type") == "risk_assessment":
            searchable.update({
                "risk_score": event_data.get("risk_score"),
                "confidence": event_data.get("confidence"),
                "detection_method": event_data.get("detection_method"),
                "risk_factors": event_data.get("risk_factors", []),
                "language": event_data.get("language"),
                "conversation_turn": event_data.get("conversation_turn")
            })
        elif event_dict.get("event_type") == "agent_activation":
            searchable.update({
                "was_activated": event_data.get("was_activated"),
                "persona_selected": event_data.get("persona_selected"),
                "activation_probability": event_data.get("activation_probability")
            })
        elif event_dict.get("event_type") == "entity_extraction":
            searchable.update({
                "entities_count": len(event_data.get("entities_found", [])),
                "extraction_method": event_data.get("extraction_method"),
                "confidence_threshold": event_data.get("confidence_threshold")
            })
        elif event_dict.get("event_type") == "safety_intervention":
            searchable.update({
                "intervention_type": event_data.get("intervention_type"),
                "trigger_reason": event_data.get("trigger_reason"),
                "safety_score": event_data.get("safety_score"),
                "action_taken": event_data.get("action_taken")
            })
        
        return searchable


# Global audit logger instance
audit_logger = AuditLogger()