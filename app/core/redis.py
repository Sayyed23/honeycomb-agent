"""
Redis connection management and caching utilities.
Provides connection pooling, session state caching, and cleanup procedures.
"""

import redis.asyncio as redis
from redis.asyncio import ConnectionPool
from typing import Optional, Any, Dict, List
import json
import logging
from datetime import datetime, timedelta
import asyncio
from contextlib import asynccontextmanager

from config.settings import settings

logger = logging.getLogger(__name__)

# Global Redis connection pool
_redis_pool: Optional[ConnectionPool] = None
_redis_client: Optional[redis.Redis] = None


class RedisConnectionManager:
    """Manages Redis connection pool and client lifecycle."""
    
    def __init__(self):
        self.pool: Optional[ConnectionPool] = None
        self.client: Optional[redis.Redis] = None
    
    async def initialize(self) -> None:
        """Initialize Redis connection pool and client. Does not block startup on failure."""
        try:
            # Create connection pool (short timeout so startup is not blocked when Redis is unavailable)
            connect_timeout = min(2, settings.redis.socket_connect_timeout)
            self.pool = ConnectionPool.from_url(
                settings.redis.url,
                max_connections=settings.redis.max_connections,
                socket_timeout=settings.redis.socket_timeout,
                socket_connect_timeout=connect_timeout,
                retry_on_timeout=settings.redis.retry_on_timeout,
                decode_responses=True,
                encoding='utf-8'
            )
            self.client = redis.Redis(connection_pool=self.pool)
            # Short timeout for ping so Railway healthcheck can pass quickly when Redis is down
            await asyncio.wait_for(self.client.ping(), timeout=2.0)
            logger.info("Redis connection initialized successfully")
        except asyncio.TimeoutError:
            logger.warning("Redis connection timed out during startup (non-fatal)")
            self.client = None
            self.pool = None
        except Exception as e:
            logger.warning("Redis unavailable at startup (non-fatal): %s", e)
            self.client = None
            self.pool = None
    
    async def close(self) -> None:
        """Close Redis connection and cleanup resources."""
        try:
            if self.client:
                await self.client.close()
            if self.pool:
                await self.pool.disconnect()
            logger.info("Redis connection closed successfully")
        except Exception as e:
            logger.error(f"Error closing Redis connection: {e}")
    
    async def health_check(self) -> bool:
        """Check Redis connectivity and health."""
        try:
            if not self.client:
                return False
            
            # Test basic operations
            await self.client.ping()
            test_key = "health_check_test"
            await self.client.set(test_key, "test", ex=1)
            result = await self.client.get(test_key)
            await self.client.delete(test_key)
            
            return result == "test"
        except Exception as e:
            logger.error(f"Redis health check failed: {e}")
            return False


# Global connection manager instance
redis_manager = RedisConnectionManager()


async def get_redis() -> redis.Redis:
    """
    Get Redis client instance.
    
    Returns:
        redis.Redis: Redis client instance
        
    Raises:
        RuntimeError: If Redis is not initialized
    """
    if not redis_manager.client:
        raise RuntimeError("Redis client not initialized. Call redis_manager.initialize() first.")
    return redis_manager.client


class CacheKeyBuilder:
    """Utility class for building consistent cache keys."""
    
    @staticmethod
    def session_state(session_id: str) -> str:
        """Build cache key for session state."""
        return f"session:{session_id}:state"
    
    @staticmethod
    def risk_score(message_hash: str) -> str:
        """Build cache key for risk score."""
        return f"risk:{message_hash}:score"
    
    @staticmethod
    def entity_validation(entity_type: str, entity_value: str) -> str:
        """Build cache key for entity validation."""
        return f"entity:{entity_type}:{entity_value}:valid"
    
    @staticmethod
    def conversation_context(session_id: str) -> str:
        """Build cache key for conversation context."""
        return f"context:{session_id}:summary"
    
    @staticmethod
    def session_lock(session_id: str) -> str:
        """Build cache key for session lock."""
        return f"lock:session:{session_id}"


class CacheManager:
    """High-level caching utilities for application data."""
    
    def __init__(self):
        self.key_builder = CacheKeyBuilder()
    
    async def get_client(self) -> redis.Redis:
        """Get Redis client instance."""
        return await get_redis()
    
    # Session State Management
    async def set_session_state(self, session_id: str, state: Dict[str, Any], ttl: int = 1800) -> bool:
        """
        Cache session state data.
        
        Args:
            session_id: Unique session identifier
            state: Session state dictionary
            ttl: Time to live in seconds (default: 30 minutes)
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            client = await self.get_client()
            key = self.key_builder.session_state(session_id)
            serialized_state = json.dumps(state, default=str)
            
            result = await client.set(key, serialized_state, ex=ttl)
            logger.debug(f"Cached session state for {session_id}")
            return bool(result)
        except Exception as e:
            logger.error(f"Failed to cache session state for {session_id}: {e}")
            return False
    
    async def get_session_state(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve cached session state.
        
        Args:
            session_id: Unique session identifier
            
        Returns:
            Optional[Dict]: Session state if found, None otherwise
        """
        try:
            client = await self.get_client()
            key = self.key_builder.session_state(session_id)
            
            cached_data = await client.get(key)
            if cached_data:
                state = json.loads(cached_data)
                logger.debug(f"Retrieved session state for {session_id}")
                return state
            return None
        except Exception as e:
            logger.error(f"Failed to retrieve session state for {session_id}: {e}")
            return None
    
    async def delete_session_state(self, session_id: str) -> bool:
        """
        Delete cached session state.
        
        Args:
            session_id: Unique session identifier
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            client = await self.get_client()
            key = self.key_builder.session_state(session_id)
            
            result = await client.delete(key)
            logger.debug(f"Deleted session state for {session_id}")
            return bool(result)
        except Exception as e:
            logger.error(f"Failed to delete session state for {session_id}: {e}")
            return False
    
    # Risk Score Caching
    async def set_risk_score(self, message_hash: str, risk_data: Dict[str, Any], ttl: int = 3600) -> bool:
        """
        Cache risk score data.
        
        Args:
            message_hash: Hash of the message content
            risk_data: Risk assessment data including score and confidence
            ttl: Time to live in seconds (default: 1 hour)
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            client = await self.get_client()
            key = self.key_builder.risk_score(message_hash)
            serialized_data = json.dumps(risk_data, default=str)
            
            result = await client.set(key, serialized_data, ex=ttl)
            logger.debug(f"Cached risk score for message hash {message_hash}")
            return bool(result)
        except Exception as e:
            logger.error(f"Failed to cache risk score for {message_hash}: {e}")
            return False
    
    async def get_risk_score(self, message_hash: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve cached risk score.
        
        Args:
            message_hash: Hash of the message content
            
        Returns:
            Optional[Dict]: Risk data if found, None otherwise
        """
        try:
            client = await self.get_client()
            key = self.key_builder.risk_score(message_hash)
            
            cached_data = await client.get(key)
            if cached_data:
                risk_data = json.loads(cached_data)
                logger.debug(f"Retrieved risk score for message hash {message_hash}")
                return risk_data
            return None
        except Exception as e:
            logger.error(f"Failed to retrieve risk score for {message_hash}: {e}")
            return None
    
    # Entity Validation Caching
    async def set_entity_validation(self, entity_type: str, entity_value: str, 
                                  is_valid: bool, ttl: int = 86400) -> bool:
        """
        Cache entity validation result.
        
        Args:
            entity_type: Type of entity (upi, phone, email, etc.)
            entity_value: Entity value to validate
            is_valid: Validation result
            ttl: Time to live in seconds (default: 24 hours)
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            client = await self.get_client()
            key = self.key_builder.entity_validation(entity_type, entity_value)
            
            result = await client.set(key, str(is_valid).lower(), ex=ttl)
            logger.debug(f"Cached entity validation for {entity_type}")
            return bool(result)
        except Exception as e:
            logger.error(f"Failed to cache entity validation for {entity_type}: {e}")
            return False
    
    async def get_entity_validation(self, entity_type: str, entity_value: str) -> Optional[bool]:
        """
        Retrieve cached entity validation result.
        
        Args:
            entity_type: Type of entity
            entity_value: Entity value
            
        Returns:
            Optional[bool]: Validation result if found, None otherwise
        """
        try:
            client = await self.get_client()
            key = self.key_builder.entity_validation(entity_type, entity_value)
            
            cached_data = await client.get(key)
            if cached_data:
                is_valid = cached_data.lower() == 'true'
                logger.debug(f"Retrieved entity validation for {entity_type}")
                return is_valid
            return None
        except Exception as e:
            logger.error(f"Failed to retrieve entity validation for {entity_type}: {e}")
            return None    # Conversation Context Caching
    async def set_conversation_context(self, session_id: str, context: str, ttl: int = 1800) -> bool:
        """
        Cache conversation context summary.
        
        Args:
            session_id: Unique session identifier
            context: Conversation context summary
            ttl: Time to live in seconds (default: 30 minutes)
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            client = await self.get_client()
            key = self.key_builder.conversation_context(session_id)
            
            result = await client.set(key, context, ex=ttl)
            logger.debug(f"Cached conversation context for {session_id}")
            return bool(result)
        except Exception as e:
            logger.error(f"Failed to cache conversation context for {session_id}: {e}")
            return False
    
    async def get_conversation_context(self, session_id: str) -> Optional[str]:
        """
        Retrieve cached conversation context.
        
        Args:
            session_id: Unique session identifier
            
        Returns:
            Optional[str]: Context summary if found, None otherwise
        """
        try:
            client = await self.get_client()
            key = self.key_builder.conversation_context(session_id)
            
            context = await client.get(key)
            if context:
                logger.debug(f"Retrieved conversation context for {session_id}")
                return context
            return None
        except Exception as e:
            logger.error(f"Failed to retrieve conversation context for {session_id}: {e}")
            return None


# Global cache manager instance
cache_manager = CacheManager()