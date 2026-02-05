"""
Session lifecycle management with Redis-backed state persistence.
Handles session creation, state management, and cleanup procedures.
"""

import asyncio
import hashlib
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict
from enum import Enum

from .redis import cache_manager, get_redis, CacheKeyBuilder

logger = logging.getLogger(__name__)


class SessionStatus(Enum):
    """Session status enumeration."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    COMPLETED = "completed"
    EXPIRED = "expired"
    ERROR = "error"


@dataclass
class SessionMetrics:
    """Session performance and engagement metrics."""
    total_turns: int = 0
    start_time: Optional[datetime] = None
    last_activity: Optional[datetime] = None
    engagement_duration: int = 0  # seconds
    risk_score: float = 0.0
    confidence_level: float = 0.0
    agent_activated: bool = False
    persona_type: Optional[str] = None


@dataclass
class SessionState:
    """Complete session state data structure."""
    session_id: str
    status: SessionStatus
    metrics: SessionMetrics
    conversation_history: List[Dict[str, Any]]
    extracted_entities: List[Dict[str, Any]]
    risk_assessments: List[Dict[str, Any]]
    metadata: Dict[str, Any]
    created_at: datetime
    updated_at: datetime
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert session state to dictionary for serialization."""
        # Convert metrics to dict and handle datetime serialization
        metrics_dict = asdict(self.metrics)
        if metrics_dict.get('start_time'):
            metrics_dict['start_time'] = metrics_dict['start_time'].isoformat()
        if metrics_dict.get('last_activity'):
            metrics_dict['last_activity'] = metrics_dict['last_activity'].isoformat()
        
        return {
            'session_id': self.session_id,
            'status': self.status.value,
            'metrics': metrics_dict,
            'conversation_history': self.conversation_history,
            'extracted_entities': self.extracted_entities,
            'risk_assessments': self.risk_assessments,
            'metadata': self.metadata,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SessionState':
        """Create session state from dictionary."""
        metrics_data = data.get('metrics', {})
        
        # Handle datetime fields in metrics
        if 'start_time' in metrics_data and metrics_data['start_time']:
            metrics_data['start_time'] = datetime.fromisoformat(metrics_data['start_time'])
        if 'last_activity' in metrics_data and metrics_data['last_activity']:
            metrics_data['last_activity'] = datetime.fromisoformat(metrics_data['last_activity'])
        
        return cls(
            session_id=data['session_id'],
            status=SessionStatus(data['status']),
            metrics=SessionMetrics(**metrics_data),
            conversation_history=data.get('conversation_history', []),
            extracted_entities=data.get('extracted_entities', []),
            risk_assessments=data.get('risk_assessments', []),
            metadata=data.get('metadata', {}),
            created_at=datetime.fromisoformat(data['created_at']) if data.get('created_at') else datetime.utcnow(),
            updated_at=datetime.fromisoformat(data['updated_at']) if data.get('updated_at') else datetime.utcnow()
        )


class SessionManager:
    """Manages session lifecycle with Redis-backed persistence."""
    
    def __init__(self):
        self.cache = cache_manager
        self.key_builder = CacheKeyBuilder()
        self._cleanup_task: Optional[asyncio.Task] = None
    
    async def create_session(self, session_id: str, metadata: Optional[Dict[str, Any]] = None) -> SessionState:
        """
        Create a new session with initial state.
        
        Args:
            session_id: Unique session identifier
            metadata: Optional session metadata
            
        Returns:
            SessionState: Newly created session state
        """
        now = datetime.utcnow()
        
        session_state = SessionState(
            session_id=session_id,
            status=SessionStatus.ACTIVE,
            metrics=SessionMetrics(start_time=now, last_activity=now),
            conversation_history=[],
            extracted_entities=[],
            risk_assessments=[],
            metadata=metadata or {},
            created_at=now,
            updated_at=now
        )
        
        # Cache the session state
        success = await self.cache.set_session_state(session_id, session_state.to_dict())
        if not success:
            logger.warning(f"Failed to cache session state for {session_id}")
        
        logger.info(f"Created new session: {session_id}")
        return session_state
    
    async def get_session(self, session_id: str) -> Optional[SessionState]:
        """
        Retrieve session state by ID.
        
        Args:
            session_id: Unique session identifier
            
        Returns:
            Optional[SessionState]: Session state if found, None otherwise
        """
        cached_data = await self.cache.get_session_state(session_id)
        if cached_data:
            try:
                return SessionState.from_dict(cached_data)
            except Exception as e:
                logger.error(f"Failed to deserialize session state for {session_id}: {e}")
                return None
        
        logger.debug(f"Session not found in cache: {session_id}")
        return None
    
    async def update_session(self, session_state: SessionState) -> bool:
        """
        Update session state in cache.
        
        Args:
            session_state: Updated session state
            
        Returns:
            bool: True if successful, False otherwise
        """
        session_state.updated_at = datetime.utcnow()
        session_state.metrics.last_activity = datetime.utcnow()
        
        success = await self.cache.set_session_state(
            session_state.session_id, 
            session_state.to_dict()
        )
        
        if success:
            logger.debug(f"Updated session state: {session_state.session_id}")
        else:
            logger.error(f"Failed to update session state: {session_state.session_id}")
        
        return success
    
    async def add_message(self, session_id: str, role: str, content: str, 
                         metadata: Optional[Dict[str, Any]] = None) -> bool:
        """
        Add a message to the session conversation history.
        
        Args:
            session_id: Unique session identifier
            role: Message role ('user' or 'assistant')
            content: Message content
            metadata: Optional message metadata
            
        Returns:
            bool: True if successful, False otherwise
        """
        session_state = await self.get_session(session_id)
        if not session_state:
            logger.error(f"Session not found: {session_id}")
            return False
        
        message = {
            'role': role,
            'content': content,
            'timestamp': datetime.utcnow().isoformat(),
            'metadata': metadata or {}
        }
        
        session_state.conversation_history.append(message)
        session_state.metrics.total_turns += 1 if role == 'user' else 0
        
        return await self.update_session(session_state)
    
    async def add_risk_assessment(self, session_id: str, risk_score: float, 
                                confidence: float, method: str, 
                                factors: Optional[Dict[str, Any]] = None) -> bool:
        """
        Add a risk assessment to the session.
        
        Args:
            session_id: Unique session identifier
            risk_score: Risk score (0.0-1.0)
            confidence: Confidence level (0.0-1.0)
            method: Detection method used
            factors: Optional risk factors
            
        Returns:
            bool: True if successful, False otherwise
        """
        session_state = await self.get_session(session_id)
        if not session_state:
            logger.error(f"Session not found: {session_id}")
            return False
        
        risk_assessment = {
            'risk_score': risk_score,
            'confidence': confidence,
            'method': method,
            'factors': factors or {},
            'timestamp': datetime.utcnow().isoformat()
        }
        
        session_state.risk_assessments.append(risk_assessment)
        session_state.metrics.risk_score = risk_score
        session_state.metrics.confidence_level = confidence
        
        return await self.update_session(session_state)
    
    async def add_extracted_entity(self, session_id: str, entity_type: str, 
                                 entity_value: str, confidence: float,
                                 context: Optional[str] = None) -> bool:
        """
        Add an extracted entity to the session.
        
        Args:
            session_id: Unique session identifier
            entity_type: Type of entity (upi, phone, email, etc.)
            entity_value: Entity value
            confidence: Extraction confidence (0.0-1.0)
            context: Optional extraction context
            
        Returns:
            bool: True if successful, False otherwise
        """
        session_state = await self.get_session(session_id)
        if not session_state:
            logger.error(f"Session not found: {session_id}")
            return False
        
        entity = {
            'entity_type': entity_type,
            'entity_value': entity_value,
            'confidence': confidence,
            'context': context,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        session_state.extracted_entities.append(entity)
        
        return await self.update_session(session_state)
    
    async def activate_agent(self, session_id: str, persona_type: str) -> bool:
        """
        Mark agent as activated for the session.
        
        Args:
            session_id: Unique session identifier
            persona_type: Selected persona type
            
        Returns:
            bool: True if successful, False otherwise
        """
        session_state = await self.get_session(session_id)
        if not session_state:
            logger.error(f"Session not found: {session_id}")
            return False
        
        session_state.metrics.agent_activated = True
        session_state.metrics.persona_type = persona_type
        
        return await self.update_session(session_state)
    
    async def complete_session(self, session_id: str) -> bool:
        """
        Mark session as completed and calculate final metrics.
        
        Args:
            session_id: Unique session identifier
            
        Returns:
            bool: True if successful, False otherwise
        """
        session_state = await self.get_session(session_id)
        if not session_state:
            logger.error(f"Session not found: {session_id}")
            return False
        
        session_state.status = SessionStatus.COMPLETED
        
        # Calculate engagement duration
        if session_state.metrics.start_time:
            duration = datetime.utcnow() - session_state.metrics.start_time
            session_state.metrics.engagement_duration = int(duration.total_seconds())
        
        success = await self.update_session(session_state)
        if success:
            logger.info(f"Completed session: {session_id}")
        
        return success
    
    async def expire_session(self, session_id: str) -> bool:
        """
        Mark session as expired due to inactivity.
        
        Args:
            session_id: Unique session identifier
            
        Returns:
            bool: True if successful, False otherwise
        """
        session_state = await self.get_session(session_id)
        if not session_state:
            return True  # Already gone
        
        session_state.status = SessionStatus.EXPIRED
        
        success = await self.update_session(session_state)
        if success:
            logger.info(f"Expired session: {session_id}")
        
        return success
    
    async def delete_session(self, session_id: str) -> bool:
        """
        Delete session from cache.
        
        Args:
            session_id: Unique session identifier
            
        Returns:
            bool: True if successful, False otherwise
        """
        success = await self.cache.delete_session_state(session_id)
        if success:
            logger.info(f"Deleted session: {session_id}")
        
        return success
    
    async def get_active_sessions(self) -> List[str]:
        """
        Get list of active session IDs.
        
        Returns:
            List[str]: List of active session IDs
        """
        try:
            client = await get_redis()
            pattern = "session:*:state"
            keys = await client.keys(pattern)
            
            active_sessions = []
            for key in keys:
                # Extract session ID from key
                session_id = key.split(':')[1]
                session_state = await self.get_session(session_id)
                
                if session_state and session_state.status == SessionStatus.ACTIVE:
                    active_sessions.append(session_id)
            
            return active_sessions
        except Exception as e:
            logger.error(f"Failed to get active sessions: {e}")
            return []
    
    async def cleanup_expired_sessions(self, max_age_hours: int = 24) -> int:
        """
        Clean up expired and old sessions.
        
        Args:
            max_age_hours: Maximum age in hours before cleanup
            
        Returns:
            int: Number of sessions cleaned up
        """
        try:
            client = await get_redis()
            pattern = "session:*:state"
            keys = await client.keys(pattern)
            
            cutoff_time = datetime.utcnow() - timedelta(hours=max_age_hours)
            cleaned_count = 0
            
            for key in keys:
                try:
                    # Extract session ID from key
                    session_id = key.split(':')[1]
                    session_state = await self.get_session(session_id)
                    
                    if not session_state:
                        continue
                    
                    # Check if session should be cleaned up
                    should_cleanup = (
                        session_state.status in [SessionStatus.COMPLETED, SessionStatus.EXPIRED] or
                        (session_state.metrics.last_activity and 
                         session_state.metrics.last_activity < cutoff_time)
                    )
                    
                    if should_cleanup:
                        await self.delete_session(session_id)
                        cleaned_count += 1
                        
                except Exception as e:
                    logger.error(f"Error processing session {key}: {e}")
                    continue
            
            if cleaned_count > 0:
                logger.info(f"Cleaned up {cleaned_count} expired sessions")
            
            return cleaned_count
            
        except Exception as e:
            logger.error(f"Failed to cleanup expired sessions: {e}")
            return 0
    
    async def start_cleanup_task(self, interval_minutes: int = 30) -> None:
        """
        Start background task for periodic session cleanup.
        
        Args:
            interval_minutes: Cleanup interval in minutes
        """
        if self._cleanup_task and not self._cleanup_task.done():
            logger.warning("Cleanup task already running")
            return
        
        async def cleanup_loop():
            while True:
                try:
                    await asyncio.sleep(interval_minutes * 60)
                    await self.cleanup_expired_sessions()
                except asyncio.CancelledError:
                    logger.info("Session cleanup task cancelled")
                    break
                except Exception as e:
                    logger.error(f"Error in session cleanup task: {e}")
                    # Continue running even if cleanup fails
        
        try:
            self._cleanup_task = asyncio.create_task(cleanup_loop())
            logger.info(f"Started session cleanup task with {interval_minutes} minute interval")
        except Exception as e:
            logger.error(f"Failed to start session cleanup task: {e}")
            raise
    
    async def stop_cleanup_task(self) -> None:
        """Stop background cleanup task."""
        if self._cleanup_task and not self._cleanup_task.done():
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
            logger.info("Stopped session cleanup task")


# Global session manager instance
session_manager = SessionManager()