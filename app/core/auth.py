"""
Authentication and authorization utilities for API key management.
"""

import hashlib
import secrets
import hmac
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Tuple
from fastapi import HTTPException, Request, Depends
from sqlalchemy.orm import Session
from sqlalchemy import and_

from app.database.connection import get_db
from app.database.models import APIKey, APIKeyUsage
from app.core.logging import get_logger
from app.core.metrics import MetricsCollector
from config.settings import settings

logger = get_logger(__name__)


class APIKeyManager:
    """Manager class for API key operations."""
    
    @staticmethod
    def generate_api_key() -> str:
        """
        Generate a new API key.
        
        Returns:
            str: A secure 32-character API key
        """
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def hash_api_key(api_key: str) -> bytes:
        """
        Hash an API key for secure storage.
        
        Args:
            api_key: The API key to hash
            
        Returns:
            bytes: The hashed API key
        """
        # Use PBKDF2 with SHA-256 for secure key hashing
        salt = settings.api_key_secret.encode('utf-8')
        return hashlib.pbkdf2_hmac('sha256', api_key.encode('utf-8'), salt, 100000)
    
    @staticmethod
    def verify_api_key(api_key: str, key_hash: bytes) -> bool:
        """
        Verify an API key against its hash.
        
        Args:
            api_key: The API key to verify
            key_hash: The stored hash to verify against
            
        Returns:
            bool: True if the key is valid
        """
        computed_hash = APIKeyManager.hash_api_key(api_key)
        return hmac.compare_digest(computed_hash, key_hash)
    
    @staticmethod
    def get_key_prefix(api_key: str) -> str:
        """
        Get the prefix of an API key for identification.
        
        Args:
            api_key: The API key
            
        Returns:
            str: The first 8 characters of the key
        """
        return api_key[:8] if len(api_key) >= 8 else api_key
    
    @staticmethod
    async def create_api_key(
        db: Session,
        key_name: str,
        description: Optional[str] = None,
        rate_limit_per_hour: int = 1000,
        permissions: Optional[Dict[str, Any]] = None,
        created_by: Optional[str] = None,
        expires_at: Optional[datetime] = None
    ) -> Tuple[str, APIKey]:
        """
        Create a new API key.
        
        Args:
            db: Database session
            key_name: Human-readable name for the key
            description: Optional description
            rate_limit_per_hour: Rate limit for this key
            permissions: Optional permissions object
            created_by: Who created this key
            expires_at: Optional expiration date
            
        Returns:
            Tuple[str, APIKey]: The generated API key and the database record
        """
        # Generate new API key
        api_key = APIKeyManager.generate_api_key()
        key_hash = APIKeyManager.hash_api_key(api_key)
        key_prefix = APIKeyManager.get_key_prefix(api_key)
        
        # Create database record
        db_key = APIKey(
            key_name=key_name,
            key_hash=key_hash,
            key_prefix=key_prefix,
            description=description,
            rate_limit_per_hour=rate_limit_per_hour,
            permissions=permissions,
            created_by=created_by,
            expires_at=expires_at
        )
        
        db.add(db_key)
        db.commit()
        db.refresh(db_key)
        
        logger.info(
            "API key created",
            extra={
                "key_name": key_name,
                "key_prefix": key_prefix,
                "rate_limit": rate_limit_per_hour,
                "created_by": created_by
            }
        )
        
        return api_key, db_key
    
    @staticmethod
    async def validate_api_key(db: Session, api_key: str) -> Optional[APIKey]:
        """
        Validate an API key and return the associated record.
        
        Args:
            db: Database session
            api_key: The API key to validate
            
        Returns:
            Optional[APIKey]: The API key record if valid, None otherwise
        """
        if not api_key:
            return None
        
        key_prefix = APIKeyManager.get_key_prefix(api_key)
        
        # Find potential matching keys by prefix
        potential_keys = db.query(APIKey).filter(
            and_(
                APIKey.key_prefix == key_prefix,
                APIKey.is_active == True
            )
        ).all()
        
        # Verify the full key against each potential match
        for db_key in potential_keys:
            if APIKeyManager.verify_api_key(api_key, db_key.key_hash):
                # Check if key has expired
                if db_key.expires_at and db_key.expires_at < datetime.utcnow():
                    logger.warning(
                        "Expired API key used",
                        extra={
                            "key_name": db_key.key_name,
                            "key_prefix": db_key.key_prefix,
                            "expired_at": db_key.expires_at
                        }
                    )
                    return None
                
                return db_key
        
        return None
    
    @staticmethod
    async def check_rate_limit(db: Session, api_key_record: APIKey) -> bool:
        """
        Check if an API key has exceeded its rate limit.
        
        Args:
            db: Database session
            api_key_record: The API key record
            
        Returns:
            bool: True if within rate limit, False if exceeded
        """
        now = datetime.utcnow()
        current_hour = now.replace(minute=0, second=0, microsecond=0)
        
        # Reset hour usage if we're in a new hour
        if (api_key_record.current_hour_start is None or 
            api_key_record.current_hour_start < current_hour):
            api_key_record.current_hour_usage = 0
            api_key_record.current_hour_start = current_hour
        
        # Check if rate limit exceeded
        if api_key_record.current_hour_usage >= api_key_record.rate_limit_per_hour:
            logger.warning(
                "Rate limit exceeded",
                extra={
                    "key_name": api_key_record.key_name,
                    "key_prefix": api_key_record.key_prefix,
                    "usage": api_key_record.current_hour_usage,
                    "limit": api_key_record.rate_limit_per_hour
                }
            )
            return False
        
        return True
    
    @staticmethod
    async def record_api_usage(
        db: Session,
        api_key_record: APIKey,
        request: Request,
        status_code: int,
        response_time_ms: Optional[int] = None,
        request_size: Optional[int] = None,
        response_size: Optional[int] = None
    ):
        """
        Record API key usage.
        
        Args:
            db: Database session
            api_key_record: The API key record
            request: FastAPI request object
            status_code: HTTP status code
            response_time_ms: Response time in milliseconds
            request_size: Request body size in bytes
            response_size: Response body size in bytes
        """
        # Update API key usage counters
        api_key_record.usage_count += 1
        api_key_record.current_hour_usage += 1
        api_key_record.last_used = datetime.utcnow()
        
        # Create detailed usage record
        usage_record = APIKeyUsage(
            api_key_id=api_key_record.id,
            endpoint=request.url.path,
            method=request.method,
            status_code=status_code,
            client_ip=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            response_time_ms=response_time_ms,
            request_size=request_size,
            response_size=response_size
        )
        
        db.add(usage_record)
        db.commit()
        
        # Record metrics
        MetricsCollector.record_database_operation("insert", "api_key_usage", "success")


class RateLimiter:
    """Rate limiting utilities."""
    
    @staticmethod
    def get_rate_limit_headers(api_key_record: APIKey) -> Dict[str, str]:
        """
        Get rate limit headers for response.
        
        Args:
            api_key_record: The API key record
            
        Returns:
            Dict[str, str]: Rate limit headers
        """
        remaining = max(0, api_key_record.rate_limit_per_hour - api_key_record.current_hour_usage)
        reset_time = api_key_record.current_hour_start + timedelta(hours=1) if api_key_record.current_hour_start else datetime.utcnow() + timedelta(hours=1)
        
        return {
            "X-RateLimit-Limit": str(api_key_record.rate_limit_per_hour),
            "X-RateLimit-Remaining": str(remaining),
            "X-RateLimit-Reset": str(int(reset_time.timestamp()))
        }


async def validate_api_key_dependency(
    request: Request,
    db: Session = Depends(get_db)
) -> APIKey:
    """
    FastAPI dependency for API key validation.
    
    Args:
        request: FastAPI request object
        db: Database session
        
    Returns:
        APIKey: Validated API key record
        
    Raises:
        HTTPException: If API key is missing, invalid, or rate limited
    """
    # Get API key from header
    api_key = request.headers.get("x-api-key")
    
    if not api_key:
        logger.warning(
            "API request without API key",
            extra={
                "client_ip": request.client.host if request.client else None,
                "user_agent": request.headers.get("user-agent"),
                "endpoint": request.url.path
            }
        )
        raise HTTPException(
            status_code=401,
            detail="Missing x-api-key header",
            headers={"WWW-Authenticate": "ApiKey"}
        )
    
    # Validate API key
    api_key_record = await APIKeyManager.validate_api_key(db, api_key)
    
    if not api_key_record:
        logger.warning(
            "API request with invalid API key",
            extra={
                "client_ip": request.client.host if request.client else None,
                "user_agent": request.headers.get("user-agent"),
                "endpoint": str(request.url),
                "key_prefix": APIKeyManager.get_key_prefix(api_key)
            }
        )
        raise HTTPException(
            status_code=403,
            detail="Invalid or expired API key"
        )
    
    # Check rate limit
    if not await APIKeyManager.check_rate_limit(db, api_key_record):
        rate_limit_headers = RateLimiter.get_rate_limit_headers(api_key_record)
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded",
            headers=rate_limit_headers
        )
    
    return api_key_record


async def optional_api_key_dependency(
    request: Request,
    db: Session = Depends(get_db)
) -> Optional[APIKey]:
    """
    Optional API key validation for endpoints that don't require authentication.
    
    Args:
        request: FastAPI request object
        db: Database session
        
    Returns:
        Optional[APIKey]: API key record if provided and valid, None otherwise
    """
    api_key = request.headers.get("x-api-key")
    
    if not api_key:
        return None
    
    try:
        return await validate_api_key_dependency(request, db)
    except HTTPException:
        # For optional validation, we don't raise exceptions
        return None