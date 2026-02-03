"""
SQLAlchemy models for the Agentic Honeypot API.
Defines database schema and relationships.
"""

from sqlalchemy import (
    Column, String, DateTime, Integer, Text, Boolean, 
    ForeignKey, Index, CheckConstraint, LargeBinary
)
from sqlalchemy.types import Numeric
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import uuid
from datetime import datetime
from typing import Optional, Dict, Any, List

from app.database.types import UUID, JSONB

Base = declarative_base()


class APIKey(Base):
    """
    APIKey model for managing API authentication keys.
    Each key represents an authorized client with specific permissions.
    """
    __tablename__ = 'api_keys'
    
    # Primary key
    id = Column(UUID(), primary_key=True, default=uuid.uuid4)
    
    # Key identification
    key_name = Column(String(100), nullable=False)  # Human-readable name
    key_hash = Column(LargeBinary, nullable=False)  # Hashed API key
    key_prefix = Column(String(8), nullable=False, index=True)  # First 8 chars for identification
    
    # Key status and permissions
    is_active = Column(Boolean, default=True, nullable=False)
    permissions = Column(JSONB(), nullable=True)  # JSON object with permissions
    
    # Usage tracking
    last_used = Column(DateTime(timezone=True), nullable=True)
    usage_count = Column(Integer, default=0, nullable=False)
    
    # Rate limiting
    rate_limit_per_hour = Column(Integer, default=1000, nullable=False)
    current_hour_usage = Column(Integer, default=0, nullable=False)
    current_hour_start = Column(DateTime(timezone=True), nullable=True)
    
    # Key metadata
    description = Column(Text, nullable=True)
    created_by = Column(String(100), nullable=True)  # Who created this key
    
    # Audit fields
    created_at = Column(DateTime(timezone=True), default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=func.now(), onupdate=func.now(), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=True)  # Optional expiration
    
    # Constraints
    __table_args__ = (
        CheckConstraint('rate_limit_per_hour > 0', name='positive_rate_limit'),
        CheckConstraint('usage_count >= 0', name='non_negative_usage_count'),
        CheckConstraint('current_hour_usage >= 0', name='non_negative_hour_usage'),
        CheckConstraint('LENGTH(key_name) > 0', name='non_empty_key_name'),
        Index('idx_api_keys_prefix', 'key_prefix'),
        Index('idx_api_keys_active', 'is_active'),
        Index('idx_api_keys_expires', 'expires_at'),
    )
    
    def __repr__(self):
        return f"<APIKey(name='{self.key_name}', prefix='{self.key_prefix}', active={self.is_active})>"


class APIKeyUsage(Base):
    """
    APIKeyUsage model for detailed API key usage tracking.
    Each record represents a single API request.
    """
    __tablename__ = 'api_key_usage'
    
    # Primary key
    id = Column(UUID(), primary_key=True, default=uuid.uuid4)
    
    # Foreign key to API key
    api_key_id = Column(UUID(), ForeignKey('api_keys.id', ondelete='CASCADE'), nullable=False)
    
    # Request information
    endpoint = Column(String(200), nullable=False)
    method = Column(String(10), nullable=False)
    status_code = Column(Integer, nullable=False)
    
    # Client information
    client_ip = Column(String(45), nullable=True)  # IPv6 compatible
    user_agent = Column(Text, nullable=True)
    
    # Timing information
    request_timestamp = Column(DateTime(timezone=True), default=func.now(), nullable=False)
    response_time_ms = Column(Integer, nullable=True)
    
    # Additional metadata
    request_size = Column(Integer, nullable=True)  # Request body size in bytes
    response_size = Column(Integer, nullable=True)  # Response body size in bytes
    
    # Relationships
    api_key = relationship("APIKey")
    
    # Constraints
    __table_args__ = (
        CheckConstraint("method IN ('GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS')", name='valid_http_method'),
        CheckConstraint('status_code >= 100 AND status_code < 600', name='valid_status_code'),
        CheckConstraint('response_time_ms IS NULL OR response_time_ms >= 0', name='non_negative_response_time'),
        Index('idx_api_key_usage_key_timestamp', 'api_key_id', 'request_timestamp'),
        Index('idx_api_key_usage_endpoint', 'endpoint'),
        Index('idx_api_key_usage_status', 'status_code'),
        Index('idx_api_key_usage_timestamp', 'request_timestamp'),
    )
    
    def __repr__(self):
        return f"<APIKeyUsage(endpoint='{self.endpoint}', method='{self.method}', status={self.status_code})>"


class Session(Base):
    """
    Session model for tracking conversation sessions.
    Each session represents a complete interaction lifecycle.
    """
    __tablename__ = 'sessions'
    
    # Primary key
    id = Column(UUID(), primary_key=True, default=uuid.uuid4)
    
    # Session identification
    session_id = Column(String(100), unique=True, nullable=False, index=True)
    
    # Risk assessment
    risk_score = Column(Numeric(3,2), nullable=False)
    confidence_level = Column(Numeric(3,2), nullable=False)
    
    # Agent configuration
    persona_type = Column(String(50), nullable=True)  # 'digitally_naive', 'average_user', 'skeptical'
    
    # Session status
    status = Column(String(20), default='active', nullable=False)  # 'active', 'completed', 'terminated'
    
    # Timing information
    start_time = Column(DateTime(timezone=True), default=func.now(), nullable=False)
    end_time = Column(DateTime(timezone=True), nullable=True)
    
    # Conversation metrics
    total_turns = Column(Integer, default=0, nullable=False)
    engagement_duration = Column(Integer, nullable=True)  # Duration in seconds
    
    # Audit fields
    created_at = Column(DateTime(timezone=True), default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=func.now(), onupdate=func.now(), nullable=False)
    
    # Relationships
    messages = relationship("Message", back_populates="session", cascade="all, delete-orphan")
    entities = relationship("ExtractedEntity", back_populates="session", cascade="all, delete-orphan")
    risk_assessments = relationship("RiskAssessment", back_populates="session", cascade="all, delete-orphan")
    guvi_callbacks = relationship("GUVICallback", back_populates="session", cascade="all, delete-orphan")
    
    # Constraints
    __table_args__ = (
        CheckConstraint('risk_score >= 0.0 AND risk_score <= 1.0', name='valid_risk_score'),
        CheckConstraint('confidence_level >= 0.0 AND confidence_level <= 1.0', name='valid_confidence_level'),
        CheckConstraint('total_turns >= 0', name='non_negative_turns'),
        CheckConstraint('engagement_duration IS NULL OR engagement_duration >= 0', name='non_negative_duration'),
        CheckConstraint("status IN ('active', 'completed', 'terminated')", name='valid_status'),
        CheckConstraint("persona_type IS NULL OR persona_type IN ('digitally_naive', 'average_user', 'skeptical')", name='valid_persona'),
        Index('idx_sessions_risk_score', 'risk_score'),
        Index('idx_sessions_status', 'status'),
        Index('idx_sessions_start_time', 'start_time'),
    )
    
    def __repr__(self):
        return f"<Session(session_id='{self.session_id}', risk_score={self.risk_score}, status='{self.status}')>"


class Message(Base):
    """
    Message model for storing conversation history.
    Each message represents a single turn in the conversation.
    """
    __tablename__ = 'messages'
    
    # Primary key
    id = Column(UUID(), primary_key=True, default=uuid.uuid4)
    
    # Foreign key to session
    session_id = Column(UUID(), ForeignKey('sessions.id', ondelete='CASCADE'), nullable=False)
    
    # Message content
    role = Column(String(20), nullable=False)  # 'user' or 'assistant'
    content = Column(Text, nullable=False)
    language = Column(String(10), default='en', nullable=False)  # 'en', 'hi', 'hinglish'
    
    # Timing
    timestamp = Column(DateTime(timezone=True), default=func.now(), nullable=False)
    
    # Additional metadata
    message_metadata = Column(JSONB(), nullable=True)
    
    # Audit fields
    created_at = Column(DateTime(timezone=True), default=func.now(), nullable=False)
    
    # Relationships
    session = relationship("Session", back_populates="messages")
    risk_assessments = relationship("RiskAssessment", back_populates="message", cascade="all, delete-orphan")
    
    # Constraints
    __table_args__ = (
        CheckConstraint("role IN ('user', 'assistant')", name='valid_role'),
        CheckConstraint("language IN ('en', 'hi', 'hinglish')", name='valid_language'),
        CheckConstraint("LENGTH(content) > 0", name='non_empty_content'),
        Index('idx_messages_session_timestamp', 'session_id', 'timestamp'),
        Index('idx_messages_role', 'role'),
    )
    
    def __repr__(self):
        return f"<Message(role='{self.role}', content='{self.content[:50]}...', timestamp={self.timestamp})>"


class ExtractedEntity(Base):
    """
    ExtractedEntity model for storing intelligence extracted from conversations.
    Each entity represents a piece of actionable intelligence.
    """
    __tablename__ = 'extracted_entities'
    
    # Primary key
    id = Column(UUID(), primary_key=True, default=uuid.uuid4)
    
    # Foreign key to session
    session_id = Column(UUID(), ForeignKey('sessions.id', ondelete='CASCADE'), nullable=False)
    
    # Entity information
    entity_type = Column(String(50), nullable=False)  # 'upi_id', 'phone_number', 'url', 'bank_account', 'email'
    entity_value = Column(Text, nullable=False)
    confidence_score = Column(Numeric(3,2), nullable=False)
    
    # Extraction metadata
    extraction_method = Column(String(50), nullable=True)  # 'regex', 'ml_model', 'manual'
    context = Column(Text, nullable=True)  # Surrounding text context
    
    # Verification status
    verified = Column(Boolean, default=False, nullable=False)
    
    # Audit fields
    created_at = Column(DateTime(timezone=True), default=func.now(), nullable=False)
    
    # Relationships
    session = relationship("Session", back_populates="entities")
    
    # Constraints
    __table_args__ = (
        CheckConstraint('confidence_score >= 0.0 AND confidence_score <= 1.0', name='valid_confidence_score'),
        CheckConstraint("entity_type IN ('upi_id', 'phone_number', 'url', 'bank_account', 'email')", name='valid_entity_type'),
        CheckConstraint("LENGTH(entity_value) > 0", name='non_empty_entity_value'),
        Index('idx_entities_type_confidence', 'entity_type', 'confidence_score'),
        Index('idx_entities_session_type', 'session_id', 'entity_type'),
        Index('idx_entities_verified', 'verified'),
    )
    
    def __repr__(self):
        return f"<ExtractedEntity(type='{self.entity_type}', value='{self.entity_value}', confidence={self.confidence_score})>"


class RiskAssessment(Base):
    """
    RiskAssessment model for storing risk analysis results.
    Each assessment represents the risk evaluation of a message.
    """
    __tablename__ = 'risk_assessments'
    
    # Primary key
    id = Column(UUID(), primary_key=True, default=uuid.uuid4)
    
    # Foreign keys
    session_id = Column(UUID(), ForeignKey('sessions.id', ondelete='CASCADE'), nullable=False)
    message_id = Column(UUID(), ForeignKey('messages.id', ondelete='CASCADE'), nullable=False)
    
    # Risk assessment results
    risk_score = Column(Numeric(3,2), nullable=False)
    confidence = Column(Numeric(3,2), nullable=False)
    
    # Assessment metadata
    detection_method = Column(String(100), nullable=True)  # 'rule_based', 'ml_model', 'ensemble'
    risk_factors = Column(JSONB(), nullable=True)  # Detailed breakdown of risk factors
    
    # Audit fields
    created_at = Column(DateTime(timezone=True), default=func.now(), nullable=False)
    
    # Relationships
    session = relationship("Session", back_populates="risk_assessments")
    message = relationship("Message", back_populates="risk_assessments")
    
    # Constraints
    __table_args__ = (
        CheckConstraint('risk_score >= 0.0 AND risk_score <= 1.0', name='valid_risk_score_assessment'),
        CheckConstraint('confidence >= 0.0 AND confidence <= 1.0', name='valid_confidence_assessment'),
        Index('idx_risk_assessments_score', 'risk_score'),
        Index('idx_risk_assessments_session', 'session_id'),
        Index('idx_risk_assessments_message', 'message_id'),
    )
    
    def __repr__(self):
        return f"<RiskAssessment(risk_score={self.risk_score}, confidence={self.confidence}, method='{self.detection_method}')>"


class GUVICallback(Base):
    """
    GUVICallback model for tracking callback attempts to GUVI evaluation system.
    Each callback represents an attempt to send results to the GUVI platform.
    """
    __tablename__ = 'guvi_callbacks'
    
    # Primary key
    id = Column(UUID(), primary_key=True, default=uuid.uuid4)
    
    # Foreign key to session
    session_id = Column(UUID(), ForeignKey('sessions.id', ondelete='CASCADE'), nullable=False)
    
    # Callback status
    callback_status = Column(String(20), default='pending', nullable=False)  # 'pending', 'success', 'failed', 'retrying'
    
    # Callback data
    callback_payload = Column(JSONB(), nullable=True)  # The payload sent to GUVI
    
    # Response information
    response_status = Column(Integer, nullable=True)  # HTTP status code
    response_body = Column(Text, nullable=True)  # Response body from GUVI
    
    # Retry information
    retry_count = Column(Integer, default=0, nullable=False)
    last_attempt = Column(DateTime(timezone=True), nullable=True)
    
    # Audit fields
    created_at = Column(DateTime(timezone=True), default=func.now(), nullable=False)
    
    # Relationships
    session = relationship("Session", back_populates="guvi_callbacks")
    
    # Constraints
    __table_args__ = (
        CheckConstraint("callback_status IN ('pending', 'success', 'failed', 'retrying')", name='valid_callback_status'),
        CheckConstraint('retry_count >= 0', name='non_negative_retry_count'),
        Index('idx_guvi_callbacks_status', 'callback_status'),
        Index('idx_guvi_callbacks_session', 'session_id'),
        Index('idx_guvi_callbacks_last_attempt', 'last_attempt'),
    )
    
    def __repr__(self):
        return f"<GUVICallback(status='{self.callback_status}', retry_count={self.retry_count})>"