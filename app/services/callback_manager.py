"""
Callback Manager for handling GUVI callback delivery with retry logic and dead letter queue.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from contextlib import asynccontextmanager

from sqlalchemy.orm import Session
from sqlalchemy import and_, or_

from app.database.connection import get_db
from app.database.models import GUVICallback, Session as SessionModel
from app.services.guvi_callback import GUVICallbackService, CallbackStatus
from app.core.audit_logger import AuditLogger, AuditEventType
from config.settings import settings

logger = logging.getLogger(__name__)


class CallbackManager:
    """Manager for GUVI callback delivery with retry logic and dead letter queue."""
    
    def __init__(self):
        self.audit_logger = AuditLogger()
        self.is_running = False
        self.retry_task = None
        self.dead_letter_queue: List[Dict[str, Any]] = []
    
    async def start_background_tasks(self):
        """Start background tasks for callback processing."""
        if self.is_running:
            logger.warning("Callback manager is already running")
            return
        
        try:
            self.is_running = True
            self.retry_task = asyncio.create_task(self._retry_loop())
            logger.info("Callback manager background tasks started")
        except Exception as e:
            self.is_running = False
            logger.error(f"Failed to start callback manager background tasks: {e}")
            raise
    
    async def stop_background_tasks(self):
        """Stop background tasks."""
        self.is_running = False
        
        if self.retry_task:
            self.retry_task.cancel()
            try:
                await self.retry_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Callback manager background tasks stopped")
    
    async def _retry_loop(self):
        """Background loop for retrying failed callbacks."""
        while self.is_running:
            try:
                await self._process_retry_queue()
                await asyncio.sleep(60)  # Check every minute
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in retry loop: {e}")
                await asyncio.sleep(60)  # Wait before retrying
    
    async def _process_retry_queue(self):
        """Process callbacks that need retry."""
        db_gen = get_db()
        db = next(db_gen)
        
        try:
            async with GUVICallbackService() as callback_service:
                retried_count = await callback_service.retry_failed_callbacks(db)
                
                if retried_count > 0:
                    logger.info(f"Processed {retried_count} callback retries")
                
                # Move permanently failed callbacks to dead letter queue
                await self._process_dead_letter_queue(db)
                
        except Exception as e:
            logger.error(f"Error processing retry queue: {e}")
        finally:
            db.close()
    
    async def _process_dead_letter_queue(self, db: Session):
        """Move permanently failed callbacks to dead letter queue."""
        # Find callbacks that have exceeded max retries
        dead_callbacks = db.query(GUVICallback).join(SessionModel).filter(
            and_(
                GUVICallback.callback_status == CallbackStatus.FAILED.value,
                GUVICallback.retry_count >= settings.guvi.max_retries
            )
        ).all()
        
        for callback in dead_callbacks:
            # Get session info
            session = db.query(SessionModel).filter(
                SessionModel.id == callback.session_id
            ).first()
            
            if session:
                # Add to dead letter queue
                dead_letter_entry = {
                    "session_id": session.session_id,
                    "callback_id": str(callback.id),
                    "failed_at": callback.last_attempt.isoformat() if callback.last_attempt else None,
                    "retry_count": callback.retry_count,
                    "payload": callback.callback_payload,
                    "last_error": callback.response_body,
                    "moved_to_dlq_at": datetime.utcnow().isoformat()
                }
                
                self.dead_letter_queue.append(dead_letter_entry)
                
                # Update callback status to indicate it's in DLQ
                callback.callback_status = "dead_letter"
                
                # Audit log
                self.audit_logger.log_event(
                    event_type=AuditEventType.GUVI_CALLBACK,
                    session_id=session.session_id,
                    details={
                        "status": "moved_to_dead_letter_queue",
                        "retry_count": callback.retry_count,
                        "reason": "max_retries_exceeded"
                    }
                )
                
                logger.warning(f"Moved callback for session {session.session_id} to dead letter queue after {callback.retry_count} retries")
        
        if dead_callbacks:
            db.commit()
    
    async def send_callback_async(self, session_id: str) -> bool:
        """
        Send callback asynchronously with automatic retry handling.
        
        Args:
            session_id: Session identifier
            
        Returns:
            bool: True if callback was initiated successfully
        """
        db_gen = get_db()
        db = next(db_gen)
        
        try:
            async with GUVICallbackService() as callback_service:
                success = await callback_service.send_callback(db, session_id)
                
                if not success:
                    logger.info(f"Callback failed for session {session_id}, will be retried automatically")
                
                return success
                
        except Exception as e:
            logger.error(f"Error sending callback for session {session_id}: {e}")
            return False
        finally:
            db.close()
    
    def get_dead_letter_queue(self) -> List[Dict[str, Any]]:
        """Get current dead letter queue entries."""
        return self.dead_letter_queue.copy()
    
    def clear_dead_letter_queue(self) -> int:
        """Clear dead letter queue and return number of entries cleared."""
        count = len(self.dead_letter_queue)
        self.dead_letter_queue.clear()
        logger.info(f"Cleared {count} entries from dead letter queue")
        return count
    
    async def reprocess_dead_letter_entry(self, session_id: str) -> bool:
        """
        Reprocess a specific dead letter queue entry.
        
        Args:
            session_id: Session identifier to reprocess
            
        Returns:
            bool: True if reprocessing was successful
        """
        # Find entry in dead letter queue
        entry_index = None
        for i, entry in enumerate(self.dead_letter_queue):
            if entry["session_id"] == session_id:
                entry_index = i
                break
        
        if entry_index is None:
            logger.warning(f"Session {session_id} not found in dead letter queue")
            return False
        
        db_gen = get_db()
        db = next(db_gen)
        
        try:
            # Reset callback status to allow retry
            session = db.query(SessionModel).filter(
                SessionModel.session_id == session_id
            ).first()
            
            if session:
                callback = db.query(GUVICallback).filter(
                    GUVICallback.session_id == session.id
                ).first()
                
                if callback:
                    callback.callback_status = CallbackStatus.FAILED.value
                    callback.retry_count = 0  # Reset retry count
                    db.commit()
                    
                    # Remove from dead letter queue
                    self.dead_letter_queue.pop(entry_index)
                    
                    # Attempt to send callback
                    async with GUVICallbackService() as callback_service:
                        success = await callback_service.send_callback(db, session_id)
                        
                        if success:
                            logger.info(f"Successfully reprocessed dead letter entry for session {session_id}")
                        else:
                            logger.warning(f"Reprocessing failed for session {session_id}, will retry automatically")
                        
                        return success
            
            return False
            
        except Exception as e:
            logger.error(f"Error reprocessing dead letter entry for session {session_id}: {e}")
            return False
        finally:
            db.close()
    
    def get_callback_statistics(self) -> Dict[str, Any]:
        """Get callback processing statistics."""
        db_gen = get_db()
        db = next(db_gen)
        
        try:
            # Count callbacks by status
            total_callbacks = db.query(GUVICallback).count()
            successful_callbacks = db.query(GUVICallback).filter(
                GUVICallback.callback_status == CallbackStatus.SUCCESS.value
            ).count()
            failed_callbacks = db.query(GUVICallback).filter(
                GUVICallback.callback_status == CallbackStatus.FAILED.value
            ).count()
            pending_callbacks = db.query(GUVICallback).filter(
                GUVICallback.callback_status == CallbackStatus.PENDING.value
            ).count()
            retrying_callbacks = db.query(GUVICallback).filter(
                GUVICallback.callback_status == CallbackStatus.RETRYING.value
            ).count()
            dead_letter_callbacks = db.query(GUVICallback).filter(
                GUVICallback.callback_status == "dead_letter"
            ).count()
            
            # Calculate success rate
            success_rate = 0.0
            if total_callbacks > 0:
                success_rate = successful_callbacks / total_callbacks
            
            return {
                "total_callbacks": total_callbacks,
                "successful_callbacks": successful_callbacks,
                "failed_callbacks": failed_callbacks,
                "pending_callbacks": pending_callbacks,
                "retrying_callbacks": retrying_callbacks,
                "dead_letter_callbacks": dead_letter_callbacks,
                "dead_letter_queue_size": len(self.dead_letter_queue),
                "success_rate": success_rate,
                "is_running": self.is_running
            }
            
        except Exception as e:
            logger.error(f"Error getting callback statistics: {e}")
            return {
                "error": str(e),
                "is_running": self.is_running
            }
        finally:
            db.close()
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on callback system."""
        try:
            # Test GUVI endpoint connectivity
            async with GUVICallbackService() as callback_service:
                # Try to make a simple request to check connectivity
                try:
                    response = await callback_service.http_client.get(
                        settings.guvi.callback_url.replace('/api/updateHoneyPotFinalResult', '/health'),
                        timeout=5.0
                    )
                    endpoint_reachable = True
                    endpoint_status = response.status_code
                except Exception:
                    endpoint_reachable = False
                    endpoint_status = None
            
            stats = self.get_callback_statistics()
            
            return {
                "status": "healthy" if self.is_running and endpoint_reachable else "degraded",
                "manager_running": self.is_running,
                "endpoint_reachable": endpoint_reachable,
                "endpoint_status": endpoint_status,
                "statistics": stats,
                "dead_letter_queue_size": len(self.dead_letter_queue),
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error in callback health check: {e}")
            return {
                "status": "unhealthy",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }


# Global callback manager instance
callback_manager = CallbackManager()


@asynccontextmanager
async def get_callback_manager():
    """Get callback manager instance."""
    yield callback_manager