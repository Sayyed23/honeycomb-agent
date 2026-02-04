"""
GUVI Callback Service for sending evaluation results to GUVI platform.
Handles payload generation, delivery, and retry logic.
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
from enum import Enum

import httpx
from sqlalchemy.orm import Session
from sqlalchemy import and_

from app.database.models import Session as SessionModel, GUVICallback, ExtractedEntity, RiskAssessment, Message
from app.core.audit_logger import AuditLogger, AuditEventType
from app.core.metrics import MetricsCollector
from app.services.callback_security import callback_security
from config.settings import settings

logger = logging.getLogger(__name__)


class CallbackStatus(Enum):
    """GUVI callback status enumeration."""
    PENDING = "pending"
    SUCCESS = "success"
    FAILED = "failed"
    RETRYING = "retrying"


@dataclass
class GUVIPayload:
    """GUVI callback payload structure."""
    sessionId: str
    detectionResult: Dict[str, Any]
    extractedEntities: List[Dict[str, Any]]
    conversationSummary: str
    confidence: float
    timestamp: str
    systemMetrics: Dict[str, Any]


class GUVICallbackService:
    """Service for managing GUVI evaluation callbacks."""
    
    def __init__(self):
        self.audit_logger = AuditLogger()
        self.metrics = MetricsCollector()
        self.http_client = None
    
    async def __aenter__(self):
        """Async context manager entry."""
        self.http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(settings.guvi.timeout),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {settings.guvi.api_key}",
                "User-Agent": f"{settings.app_name}/{settings.app_version}"
            }
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.http_client:
            await self.http_client.aclose()
    
    def generate_callback_payload(self, db: Session, session_id: str) -> GUVIPayload:
        """
        Generate GUVI callback payload for a completed session.
        
        Args:
            db: Database session
            session_id: Session identifier
            
        Returns:
            GUVIPayload: Complete payload for GUVI callback
            
        Raises:
            ValueError: If session not found or incomplete
        """
        # Fetch session with all related data
        session = db.query(SessionModel).filter(
            SessionModel.session_id == session_id
        ).first()
        
        if not session:
            raise ValueError(f"Session {session_id} not found")
        
        if session.status != 'completed':
            raise ValueError(f"Session {session_id} is not completed (status: {session.status})")
        
        # Generate detection result
        detection_result = self._generate_detection_result(db, session)
        
        # Extract entities
        extracted_entities = self._extract_entities_data(db, session)
        
        # Generate conversation summary
        conversation_summary = self._generate_conversation_summary(db, session)
        
        # Calculate overall confidence
        confidence = self._calculate_overall_confidence(db, session)
        
        # Generate system metrics
        system_metrics = self._generate_system_metrics(db, session)
        
        payload = GUVIPayload(
            sessionId=session_id,
            detectionResult=detection_result,
            extractedEntities=extracted_entities,
            conversationSummary=conversation_summary,
            confidence=confidence,
            timestamp=datetime.utcnow().isoformat() + "Z",
            systemMetrics=system_metrics
        )
        
        logger.info(f"Generated GUVI callback payload for session {session_id}")
        return payload
    
    def _generate_detection_result(self, db: Session, session: SessionModel) -> Dict[str, Any]:
        """Generate detection result summary."""
        # Get all risk assessments for the session
        risk_assessments = db.query(RiskAssessment).filter(
            RiskAssessment.session_id == session.id
        ).all()
        
        if not risk_assessments:
            return {
                "isScam": False,
                "riskScore": 0.0,
                "confidence": 0.0,
                "detectionMethods": [],
                "riskFactors": []
            }
        
        # Calculate aggregated risk metrics
        max_risk_score = max(ra.risk_score for ra in risk_assessments)
        avg_confidence = sum(ra.confidence for ra in risk_assessments) / len(risk_assessments)
        
        # Collect detection methods and risk factors
        detection_methods = list(set(
            ra.detection_method for ra in risk_assessments 
            if ra.detection_method
        ))
        
        risk_factors = []
        for ra in risk_assessments:
            if ra.risk_factors:
                risk_factors.extend(ra.risk_factors.get('factors', []))
        
        # Remove duplicates while preserving order
        unique_risk_factors = []
        seen = set()
        for factor in risk_factors:
            if factor not in seen:
                unique_risk_factors.append(factor)
                seen.add(factor)
        
        return {
            "isScam": max_risk_score >= 0.75,  # Based on activation threshold
            "riskScore": float(max_risk_score),
            "confidence": float(avg_confidence),
            "detectionMethods": detection_methods,
            "riskFactors": unique_risk_factors,
            "assessmentCount": len(risk_assessments),
            "sessionRiskScore": float(session.risk_score),
            "sessionConfidence": float(session.confidence_level)
        }
    
    def _extract_entities_data(self, db: Session, session: SessionModel) -> List[Dict[str, Any]]:
        """Extract entities data for callback."""
        entities = db.query(ExtractedEntity).filter(
            and_(
                ExtractedEntity.session_id == session.id,
                ExtractedEntity.confidence_score >= 0.8  # Only high-confidence entities
            )
        ).all()
        
        entity_data = []
        for entity in entities:
            entity_data.append({
                "type": entity.entity_type,
                "value": entity.entity_value,
                "confidence": float(entity.confidence_score),
                "extractionMethod": entity.extraction_method,
                "context": entity.context,
                "verified": entity.verified,
                "extractedAt": entity.created_at.isoformat() + "Z"
            })
        
        return entity_data
    
    def _generate_conversation_summary(self, db: Session, session: SessionModel) -> str:
        """Generate conversation summary."""
        messages = db.query(Message).filter(
            Message.session_id == session.id
        ).order_by(Message.timestamp).all()
        
        if not messages:
            return "No conversation data available."
        
        # Create a structured summary
        summary_parts = [
            f"Session Duration: {session.engagement_duration or 0} seconds",
            f"Total Turns: {session.total_turns}",
            f"Persona Used: {session.persona_type or 'None'}",
            f"Languages Detected: {', '.join(set(msg.language for msg in messages))}",
        ]
        
        # Add conversation flow summary
        user_messages = [msg for msg in messages if msg.role == 'user']
        assistant_messages = [msg for msg in messages if msg.role == 'assistant']
        
        summary_parts.extend([
            f"User Messages: {len(user_messages)}",
            f"Assistant Messages: {len(assistant_messages)}",
        ])
        
        # Add key conversation highlights
        if user_messages:
            first_message = user_messages[0].content[:100] + "..." if len(user_messages[0].content) > 100 else user_messages[0].content
            summary_parts.append(f"Initial Message: {first_message}")
        
        if len(user_messages) > 1:
            last_message = user_messages[-1].content[:100] + "..." if len(user_messages[-1].content) > 100 else user_messages[-1].content
            summary_parts.append(f"Final Message: {last_message}")
        
        return " | ".join(summary_parts)
    
    def _calculate_overall_confidence(self, db: Session, session: SessionModel) -> float:
        """Calculate overall confidence score for the session."""
        # Get confidence from risk assessments
        risk_assessments = db.query(RiskAssessment).filter(
            RiskAssessment.session_id == session.id
        ).all()
        
        if not risk_assessments:
            return 0.0
        
        # Weight confidence by recency and risk score
        total_weighted_confidence = 0.0
        total_weight = 0.0
        
        for ra in risk_assessments:
            # Higher risk scores get more weight
            weight = float(ra.risk_score) + 0.1  # Minimum weight of 0.1
            total_weighted_confidence += float(ra.confidence) * weight
            total_weight += weight
        
        if total_weight == 0:
            return 0.0
        
        return min(total_weighted_confidence / total_weight, 1.0)
    
    def _generate_system_metrics(self, db: Session, session: SessionModel) -> Dict[str, Any]:
        """Generate system performance metrics."""
        # Calculate session timing metrics
        session_duration = 0
        if session.end_time and session.start_time:
            session_duration = (session.end_time - session.start_time).total_seconds()
        
        # Count entities by type
        entities = db.query(ExtractedEntity).filter(
            ExtractedEntity.session_id == session.id
        ).all()
        
        entity_counts = {}
        for entity in entities:
            entity_counts[entity.entity_type] = entity_counts.get(entity.entity_type, 0) + 1
        
        # Count risk assessments
        risk_assessment_count = db.query(RiskAssessment).filter(
            RiskAssessment.session_id == session.id
        ).count()
        
        return {
            "sessionDuration": session_duration,
            "engagementDuration": session.engagement_duration or 0,
            "totalTurns": session.total_turns,
            "entityCounts": entity_counts,
            "riskAssessmentCount": risk_assessment_count,
            "processingTimestamp": datetime.utcnow().isoformat() + "Z",
            "systemVersion": settings.app_version,
            "personaUsed": session.persona_type
        }
    
    async def send_callback(self, db: Session, session_id: str) -> bool:
        """
        Send callback to GUVI platform with security measures.
        
        Args:
            db: Database session
            session_id: Session identifier
            
        Returns:
            bool: True if callback was successful, False otherwise
        """
        start_time = datetime.utcnow()
        
        try:
            # Generate payload
            payload = self.generate_callback_payload(db, session_id)
            
            # Apply security sanitization
            sanitized_payload = callback_security.sanitize_payload_for_transmission(
                asdict(payload)
            )
            
            # Generate security signature
            signature = callback_security.generate_callback_signature(sanitized_payload)
            
            # Perform security audit
            audit_results = callback_security.audit_callback_security(
                session_id, sanitized_payload
            )
            
            # Reject callback if security audit fails
            if not audit_results['security_compliant']:
                logger.error(f"Security audit failed for callback {session_id}, rejecting transmission")
                
                # Update callback record with security failure
                callback_record = self._get_or_create_callback_record(db, session_id)
                callback_record.callback_status = CallbackStatus.FAILED.value
                callback_record.response_body = f"Security audit failed: {audit_results}"
                callback_record.last_attempt = start_time
                db.commit()
                
                return False
            
            # Create or update callback record
            callback_record = self._get_or_create_callback_record(db, session_id)
            callback_record.callback_payload = sanitized_payload
            callback_record.callback_status = CallbackStatus.RETRYING.value
            callback_record.last_attempt = start_time
            db.commit()
            
            # Prepare secure headers
            secure_headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {settings.guvi.api_key}",
                "User-Agent": f"{settings.app_name}/{settings.app_version}",
                "X-Callback-Signature": signature,
                "X-Security-Version": "1.0"
            }
            
            # Send HTTP request with security headers
            response = await self.http_client.post(
                settings.guvi.callback_url,
                json=sanitized_payload,
                headers=secure_headers
            )
            
            # Update callback record with response
            callback_record.response_status = response.status_code
            callback_record.response_body = response.text
            
            if response.is_success:
                callback_record.callback_status = CallbackStatus.SUCCESS.value
                success = True
                logger.info(f"GUVI callback successful for session {session_id}")
            else:
                callback_record.callback_status = CallbackStatus.FAILED.value
                success = False
                logger.error(f"GUVI callback failed for session {session_id}: {response.status_code} - {response.text}")
            
            db.commit()
            
            # Record metrics
            duration = (datetime.utcnow() - start_time).total_seconds()
            status = "success" if success else "failed"
            self.metrics.record_guvi_callback(status, duration)
            
            # Audit log with security information
            self.audit_logger.log_event(
                event_type=AuditEventType.GUVI_CALLBACK,
                session_id=session_id,
                details={
                    "status": status,
                    "response_code": response.status_code,
                    "duration": duration,
                    "payload_size": len(json.dumps(sanitized_payload)),
                    "security_audit": audit_results,
                    "signature_generated": True,
                    "payload_sanitized": True
                }
            )
            
            return success
            
        except Exception as e:
            # Update callback record with error
            callback_record = self._get_or_create_callback_record(db, session_id)
            callback_record.callback_status = CallbackStatus.FAILED.value
            callback_record.response_body = str(e)
            callback_record.last_attempt = start_time
            db.commit()
            
            # Record metrics
            duration = (datetime.utcnow() - start_time).total_seconds()
            self.metrics.record_guvi_callback("error", duration)
            
            # Audit log
            self.audit_logger.log_event(
                event_type=AuditEventType.GUVI_CALLBACK,
                session_id=session_id,
                details={
                    "status": "error",
                    "error": str(e),
                    "duration": duration,
                    "security_measures_applied": True
                }
            )
            
            logger.error(f"GUVI callback error for session {session_id}: {e}")
            return False
    
    def _get_or_create_callback_record(self, db: Session, session_id: str) -> GUVICallback:
        """Get or create GUVI callback record."""
        # Get session
        session = db.query(SessionModel).filter(
            SessionModel.session_id == session_id
        ).first()
        
        if not session:
            raise ValueError(f"Session {session_id} not found")
        
        # Get or create callback record
        callback_record = db.query(GUVICallback).filter(
            GUVICallback.session_id == session.id
        ).first()
        
        if not callback_record:
            callback_record = GUVICallback(
                session_id=session.id,
                callback_status=CallbackStatus.PENDING.value,
                retry_count=0
            )
            db.add(callback_record)
            db.flush()  # Get the ID
        
        return callback_record
    
    async def retry_failed_callbacks(self, db: Session, max_age_hours: int = 24) -> int:
        """
        Retry failed callbacks with exponential backoff.
        
        Args:
            db: Database session
            max_age_hours: Maximum age of callbacks to retry
            
        Returns:
            int: Number of callbacks retried
        """
        cutoff_time = datetime.utcnow() - timedelta(hours=max_age_hours)
        
        # Find failed callbacks that need retry
        failed_callbacks = db.query(GUVICallback).join(SessionModel).filter(
            and_(
                GUVICallback.callback_status == CallbackStatus.FAILED.value,
                GUVICallback.retry_count < settings.guvi.max_retries,
                GUVICallback.created_at >= cutoff_time
            )
        ).all()
        
        retried_count = 0
        
        for callback in failed_callbacks:
            # Calculate backoff delay
            delay = self._calculate_backoff_delay(callback.retry_count)
            
            # Check if enough time has passed since last attempt
            if callback.last_attempt:
                time_since_last = datetime.utcnow() - callback.last_attempt
                if time_since_last.total_seconds() < delay:
                    continue  # Not ready for retry yet
            
            # Increment retry count
            callback.retry_count += 1
            
            # Get session ID
            session = db.query(SessionModel).filter(
                SessionModel.id == callback.session_id
            ).first()
            
            if session:
                # Attempt retry
                success = await self.send_callback(db, session.session_id)
                if success:
                    retried_count += 1
                    logger.info(f"Successfully retried GUVI callback for session {session.session_id}")
                else:
                    logger.warning(f"Retry failed for GUVI callback for session {session.session_id}")
        
        return retried_count
    
    def _calculate_backoff_delay(self, retry_count: int) -> float:
        """Calculate exponential backoff delay."""
        delay = settings.guvi.retry_backoff_base * (
            settings.guvi.retry_backoff_multiplier ** retry_count
        )
        return min(delay, settings.guvi.retry_max_delay)
    
    def get_callback_status(self, db: Session, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Get callback status for a session.
        
        Args:
            db: Database session
            session_id: Session identifier
            
        Returns:
            Optional[Dict]: Callback status information or None if not found
        """
        session = db.query(SessionModel).filter(
            SessionModel.session_id == session_id
        ).first()
        
        if not session:
            return None
        
        callback = db.query(GUVICallback).filter(
            GUVICallback.session_id == session.id
        ).first()
        
        if not callback:
            return {
                "status": "not_initiated",
                "session_id": session_id,
                "created_at": None,
                "last_attempt": None,
                "retry_count": 0
            }
        
        return {
            "status": callback.callback_status,
            "session_id": session_id,
            "created_at": callback.created_at.isoformat() + "Z" if callback.created_at else None,
            "last_attempt": callback.last_attempt.isoformat() + "Z" if callback.last_attempt else None,
            "retry_count": callback.retry_count,
            "response_status": callback.response_status,
            "response_body": callback.response_body
        }