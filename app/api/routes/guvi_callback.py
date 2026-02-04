"""
GUVI Callback management API endpoints.
"""

from typing import Dict, Any, List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.services import callback_manager, GUVICallbackService, callback_security
from app.core.auth import validate_api_key_dependency
from app.database.models import APIKey

router = APIRouter(prefix="/api/guvi", tags=["GUVI Callbacks"])


@router.post("/callback/{session_id}")
async def trigger_callback(
    session_id: str,
    db: Session = Depends(get_db),
    api_key: APIKey = Depends(validate_api_key_dependency)
) -> Dict[str, Any]:
    """
    Manually trigger a GUVI callback for a session.
    
    Args:
        session_id: Session identifier
        db: Database session
        api_key: Validated API key
        
    Returns:
        Dict containing callback result
    """
    try:
        success = await callback_manager.send_callback_async(session_id)
        
        return {
            "status": "success" if success else "failed",
            "session_id": session_id,
            "message": "Callback sent successfully" if success else "Callback failed, will be retried automatically"
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error triggering callback: {str(e)}"
        )


@router.get("/callback/{session_id}/status")
async def get_callback_status(
    session_id: str,
    db: Session = Depends(get_db),
    api_key: APIKey = Depends(validate_api_key_dependency)
) -> Dict[str, Any]:
    """
    Get callback status for a specific session.
    
    Args:
        session_id: Session identifier
        db: Database session
        api_key: Validated API key
        
    Returns:
        Dict containing callback status information
    """
    try:
        async with GUVICallbackService() as callback_service:
            status_info = callback_service.get_callback_status(db, session_id)
            
            if status_info is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Session {session_id} not found"
                )
            
            return status_info
            
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting callback status: {str(e)}"
        )


@router.get("/callbacks/statistics")
async def get_callback_statistics(
    api_key: APIKey = Depends(validate_api_key_dependency)
) -> Dict[str, Any]:
    """
    Get overall callback processing statistics.
    
    Args:
        api_key: Validated API key
        
    Returns:
        Dict containing callback statistics
    """
    try:
        return callback_manager.get_callback_statistics()
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting callback statistics: {str(e)}"
        )


@router.get("/callbacks/health")
async def get_callback_health(
    api_key: APIKey = Depends(validate_api_key_dependency)
) -> Dict[str, Any]:
    """
    Get callback system health status.
    
    Args:
        api_key: Validated API key
        
    Returns:
        Dict containing health status
    """
    try:
        return await callback_manager.health_check()
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error checking callback health: {str(e)}"
        )


@router.get("/callbacks/dead-letter-queue")
async def get_dead_letter_queue(
    api_key: APIKey = Depends(validate_api_key_dependency)
) -> Dict[str, Any]:
    """
    Get dead letter queue entries.
    
    Args:
        api_key: Validated API key
        
    Returns:
        Dict containing dead letter queue entries
    """
    try:
        entries = callback_manager.get_dead_letter_queue()
        
        return {
            "entries": entries,
            "count": len(entries)
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting dead letter queue: {str(e)}"
        )


@router.post("/callbacks/dead-letter-queue/{session_id}/reprocess")
async def reprocess_dead_letter_entry(
    session_id: str,
    api_key: APIKey = Depends(validate_api_key_dependency)
) -> Dict[str, Any]:
    """
    Reprocess a dead letter queue entry.
    
    Args:
        session_id: Session identifier to reprocess
        api_key: Validated API key
        
    Returns:
        Dict containing reprocessing result
    """
    try:
        success = await callback_manager.reprocess_dead_letter_entry(session_id)
        
        return {
            "status": "success" if success else "failed",
            "session_id": session_id,
            "message": "Entry reprocessed successfully" if success else "Failed to reprocess entry"
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error reprocessing dead letter entry: {str(e)}"
        )


@router.delete("/callbacks/dead-letter-queue")
async def clear_dead_letter_queue(
    api_key: APIKey = Depends(validate_api_key_dependency)
) -> Dict[str, Any]:
    """
    Clear all dead letter queue entries.
    
    Args:
        api_key: Validated API key
        
    Returns:
        Dict containing clear operation result
    """
    try:
        count = callback_manager.clear_dead_letter_queue()
        
        return {
            "status": "success",
            "cleared_count": count,
            "message": f"Cleared {count} entries from dead letter queue"
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error clearing dead letter queue: {str(e)}"
        )


@router.post("/callbacks/security/audit/{session_id}")
async def audit_callback_security(
    session_id: str,
    db: Session = Depends(get_db),
    api_key: APIKey = Depends(validate_api_key_dependency)
) -> Dict[str, Any]:
    """
    Perform security audit on a callback payload.
    
    Args:
        session_id: Session identifier
        db: Database session
        api_key: Validated API key
        
    Returns:
        Dict containing security audit results
    """
    try:
        async with GUVICallbackService() as callback_service:
            # Generate payload for auditing
            payload = callback_service.generate_callback_payload(db, session_id)
            payload_dict = payload.__dict__ if hasattr(payload, '__dict__') else payload
            
            # Perform security audit
            audit_results = callback_security.audit_callback_security(
                session_id, payload_dict
            )
            
            return audit_results
            
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error performing security audit: {str(e)}"
        )


@router.post("/callbacks/security/sanitize/{session_id}")
async def preview_sanitized_payload(
    session_id: str,
    db: Session = Depends(get_db),
    api_key: APIKey = Depends(validate_api_key_dependency)
) -> Dict[str, Any]:
    """
    Preview sanitized callback payload without sending.
    
    Args:
        session_id: Session identifier
        db: Database session
        api_key: Validated API key
        
    Returns:
        Dict containing sanitized payload preview
    """
    try:
        async with GUVICallbackService() as callback_service:
            # Generate original payload
            payload = callback_service.generate_callback_payload(db, session_id)
            
            # Convert to dict if needed
            if hasattr(payload, '__dict__'):
                payload_dict = payload.__dict__
            else:
                payload_dict = payload
            
            # Apply sanitization
            sanitized_payload = callback_security.sanitize_payload_for_transmission(
                payload_dict
            )
            
            # Generate signature
            signature = callback_security.generate_callback_signature(sanitized_payload)
            
            return {
                "session_id": session_id,
                "sanitized_payload": sanitized_payload,
                "signature": signature,
                "sanitization_applied": True
            }
            
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error sanitizing payload: {str(e)}"
        )