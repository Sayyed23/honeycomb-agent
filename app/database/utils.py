"""
Database utility functions and helpers.
"""

from sqlalchemy.orm import Session as SQLAlchemySession
from sqlalchemy.exc import SQLAlchemyError
from typing import Optional, Dict, Any, List
import logging
from datetime import datetime, timedelta

from .models import Session, Message, ExtractedEntity, RiskAssessment, GUVICallback

logger = logging.getLogger(__name__)


class DatabaseManager:
    """
    Database manager class for common database operations.
    """
    
    def __init__(self, db: SQLAlchemySession):
        self.db = db
    
    def create_session(
        self,
        session_id: str,
        risk_score: float,
        confidence_level: float,
        persona_type: Optional[str] = None
    ) -> Session:
        """
        Create a new conversation session.
        
        Args:
            session_id: Unique session identifier
            risk_score: Initial risk score (0.0-1.0)
            confidence_level: Confidence in risk assessment (0.0-1.0)
            persona_type: Agent persona type (optional)
            
        Returns:
            Session: Created session object
            
        Raises:
            SQLAlchemyError: If database operation fails
        """
        try:
            session = Session(
                session_id=session_id,
                risk_score=risk_score,
                confidence_level=confidence_level,
                persona_type=persona_type,
                status='active'
            )
            
            self.db.add(session)
            self.db.commit()
            self.db.refresh(session)
            
            logger.info(f"Created session {session_id} with risk score {risk_score}")
            return session
            
        except SQLAlchemyError as e:
            self.db.rollback()
            logger.error(f"Failed to create session {session_id}: {e}")
            raise
    
    def get_session(self, session_id: str) -> Optional[Session]:
        """
        Retrieve a session by session_id.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Session: Session object if found, None otherwise
        """
        try:
            return self.db.query(Session).filter(
                Session.session_id == session_id
            ).first()
        except SQLAlchemyError as e:
            logger.error(f"Failed to retrieve session {session_id}: {e}")
            return None
    
    def add_message(
        self,
        session_id: str,
        role: str,
        content: str,
        language: str = 'en',
        metadata: Optional[Dict[str, Any]] = None
    ) -> Optional[Message]:
        """
        Add a message to a session.
        
        Args:
            session_id: Session identifier
            role: Message role ('user' or 'assistant')
            content: Message content
            language: Message language
            metadata: Additional metadata
            
        Returns:
            Message: Created message object, None if failed
        """
        try:
            # Get session
            session = self.get_session(session_id)
            if not session:
                logger.error(f"Session {session_id} not found")
                return None
            
            message = Message(
                session_id=session.id,
                role=role,
                content=content,
                language=language,
                message_metadata=metadata
            )
            
            self.db.add(message)
            
            # Update session turn count
            session.total_turns += 1
            session.updated_at = datetime.utcnow()
            
            self.db.commit()
            self.db.refresh(message)
            
            logger.debug(f"Added {role} message to session {session_id}")
            return message
            
        except SQLAlchemyError as e:
            self.db.rollback()
            logger.error(f"Failed to add message to session {session_id}: {e}")
            return None
    
    def add_risk_assessment(
        self,
        session_id: str,
        message_id: str,
        risk_score: float,
        confidence: float,
        detection_method: Optional[str] = None,
        risk_factors: Optional[Dict[str, Any]] = None
    ) -> Optional[RiskAssessment]:
        """
        Add a risk assessment for a message.
        
        Args:
            session_id: Session identifier
            message_id: Message identifier
            risk_score: Risk score (0.0-1.0)
            confidence: Confidence level (0.0-1.0)
            detection_method: Method used for detection
            risk_factors: Detailed risk factors
            
        Returns:
            RiskAssessment: Created assessment object, None if failed
        """
        try:
            session = self.get_session(session_id)
            if not session:
                logger.error(f"Session {session_id} not found")
                return None
            
            assessment = RiskAssessment(
                session_id=session.id,
                message_id=message_id,
                risk_score=risk_score,
                confidence=confidence,
                detection_method=detection_method,
                risk_factors=risk_factors
            )
            
            self.db.add(assessment)
            self.db.commit()
            self.db.refresh(assessment)
            
            logger.debug(f"Added risk assessment to session {session_id}")
            return assessment
            
        except SQLAlchemyError as e:
            self.db.rollback()
            logger.error(f"Failed to add risk assessment: {e}")
            return None
    
    def add_extracted_entity(
        self,
        session_id: str,
        entity_type: str,
        entity_value: str,
        confidence_score: float,
        extraction_method: Optional[str] = None,
        context: Optional[str] = None
    ) -> Optional[ExtractedEntity]:
        """
        Add an extracted entity to a session.
        
        Args:
            session_id: Session identifier
            entity_type: Type of entity
            entity_value: Entity value
            confidence_score: Confidence in extraction (0.0-1.0)
            extraction_method: Method used for extraction
            context: Context where entity was found
            
        Returns:
            ExtractedEntity: Created entity object, None if failed
        """
        try:
            session = self.get_session(session_id)
            if not session:
                logger.error(f"Session {session_id} not found")
                return None
            
            entity = ExtractedEntity(
                session_id=session.id,
                entity_type=entity_type,
                entity_value=entity_value,
                confidence_score=confidence_score,
                extraction_method=extraction_method,
                context=context
            )
            
            self.db.add(entity)
            self.db.commit()
            self.db.refresh(entity)
            
            logger.debug(f"Added {entity_type} entity to session {session_id}")
            return entity
            
        except SQLAlchemyError as e:
            self.db.rollback()
            logger.error(f"Failed to add extracted entity: {e}")
            return None
    
    def complete_session(
        self,
        session_id: str,
        engagement_duration: Optional[int] = None
    ) -> bool:
        """
        Mark a session as completed.
        
        Args:
            session_id: Session identifier
            engagement_duration: Total engagement duration in seconds
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            session = self.get_session(session_id)
            if not session:
                logger.error(f"Session {session_id} not found")
                return False
            
            session.status = 'completed'
            session.end_time = datetime.utcnow()
            session.updated_at = datetime.utcnow()
            
            if engagement_duration is not None:
                session.engagement_duration = engagement_duration
            
            self.db.commit()
            
            logger.info(f"Completed session {session_id}")
            return True
            
        except SQLAlchemyError as e:
            self.db.rollback()
            logger.error(f"Failed to complete session {session_id}: {e}")
            return False
    
    def get_session_messages(self, session_id: str) -> List[Message]:
        """
        Get all messages for a session, ordered by timestamp.
        
        Args:
            session_id: Session identifier
            
        Returns:
            List[Message]: List of messages
        """
        try:
            session = self.get_session(session_id)
            if not session:
                return []
            
            return self.db.query(Message).filter(
                Message.session_id == session.id
            ).order_by(Message.timestamp).all()
            
        except SQLAlchemyError as e:
            logger.error(f"Failed to get messages for session {session_id}: {e}")
            return []
    
    def get_session_entities(self, session_id: str) -> List[ExtractedEntity]:
        """
        Get all extracted entities for a session.
        
        Args:
            session_id: Session identifier
            
        Returns:
            List[ExtractedEntity]: List of extracted entities
        """
        try:
            session = self.get_session(session_id)
            if not session:
                return []
            
            return self.db.query(ExtractedEntity).filter(
                ExtractedEntity.session_id == session.id
            ).order_by(ExtractedEntity.created_at).all()
            
        except SQLAlchemyError as e:
            logger.error(f"Failed to get entities for session {session_id}: {e}")
            return []
    
    def cleanup_old_sessions(self, days_old: int = 90) -> int:
        """
        Clean up old completed sessions.
        
        Args:
            days_old: Number of days after which to clean up sessions
            
        Returns:
            int: Number of sessions cleaned up
        """
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days_old)
            
            # Fetch and delete old completed sessions (respects ORM cascades)
            old_sessions = self.db.query(Session).filter(
                Session.status == 'completed',
                Session.end_time < cutoff_date
            ).all()
            
            deleted_count = len(old_sessions)
            for session in old_sessions:
                self.db.delete(session)
            
            self.db.commit()
            
            logger.info(f"Cleaned up {deleted_count} old sessions")
            return deleted_count
            
        except SQLAlchemyError as e:
            self.db.rollback()
            logger.error(f"Failed to cleanup old sessions: {e}")
            return 0