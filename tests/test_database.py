"""
Tests for database models and functionality.
"""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import uuid

from app.database.models import Base, Session, Message, ExtractedEntity, RiskAssessment, GUVICallback
from app.database.utils import DatabaseManager


@pytest.fixture
def db_engine():
    """Create an in-memory SQLite database for testing."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    return engine


@pytest.fixture
def db_session(db_engine):
    """Create a database session for testing."""
    SessionLocal = sessionmaker(bind=db_engine)
    session = SessionLocal()
    yield session
    session.close()


@pytest.fixture
def db_manager(db_session):
    """Create a DatabaseManager instance for testing."""
    return DatabaseManager(db_session)


def test_session_model_creation(db_session):
    """Test creating a Session model instance."""
    session = Session(
        session_id="test-session-123",
        risk_score=0.85,
        confidence_level=0.90,
        persona_type="digitally_naive",
        status="active"
    )
    
    db_session.add(session)
    db_session.commit()
    
    # Verify the session was created
    retrieved_session = db_session.query(Session).filter(
        Session.session_id == "test-session-123"
    ).first()
    
    assert retrieved_session is not None
    assert retrieved_session.session_id == "test-session-123"
    assert retrieved_session.risk_score == 0.85
    assert retrieved_session.confidence_level == 0.90
    assert retrieved_session.persona_type == "digitally_naive"
    assert retrieved_session.status == "active"
    assert retrieved_session.total_turns == 0


def test_message_model_creation(db_session):
    """Test creating a Message model instance."""
    # First create a session
    session = Session(
        session_id="test-session-456",
        risk_score=0.75,
        confidence_level=0.80
    )
    db_session.add(session)
    db_session.commit()
    
    # Create a message
    message = Message(
        session_id=session.id,
        role="user",
        content="Hello, I need help with my bank account",
        language="en"
    )
    
    db_session.add(message)
    db_session.commit()
    
    # Verify the message was created
    retrieved_message = db_session.query(Message).filter(
        Message.content.contains("bank account")
    ).first()
    
    assert retrieved_message is not None
    assert retrieved_message.role == "user"
    assert retrieved_message.content == "Hello, I need help with my bank account"
    assert retrieved_message.language == "en"
    assert retrieved_message.session_id == session.id


def test_extracted_entity_model_creation(db_session):
    """Test creating an ExtractedEntity model instance."""
    # First create a session
    session = Session(
        session_id="test-session-789",
        risk_score=0.95,
        confidence_level=0.85
    )
    db_session.add(session)
    db_session.commit()
    
    # Create an extracted entity
    entity = ExtractedEntity(
        session_id=session.id,
        entity_type="phone_number",
        entity_value="+1234567890",
        confidence_score=0.92,
        extraction_method="regex",
        context="Please call me at +1234567890"
    )
    
    db_session.add(entity)
    db_session.commit()
    
    # Verify the entity was created
    retrieved_entity = db_session.query(ExtractedEntity).filter(
        ExtractedEntity.entity_value == "+1234567890"
    ).first()
    
    assert retrieved_entity is not None
    assert retrieved_entity.entity_type == "phone_number"
    assert retrieved_entity.entity_value == "+1234567890"
    assert retrieved_entity.confidence_score == 0.92
    assert retrieved_entity.extraction_method == "regex"
    assert not retrieved_entity.verified


def test_database_manager_create_session(db_manager):
    """Test DatabaseManager session creation."""
    session = db_manager.create_session(
        session_id="manager-test-123",
        risk_score=0.80,
        confidence_level=0.75,
        persona_type="average_user"
    )
    
    assert session is not None
    assert session.session_id == "manager-test-123"
    assert session.risk_score == 0.80
    assert session.confidence_level == 0.75
    assert session.persona_type == "average_user"
    assert session.status == "active"


def test_database_manager_add_message(db_manager):
    """Test DatabaseManager message addition."""
    # Create a session first
    session = db_manager.create_session(
        session_id="manager-test-456",
        risk_score=0.70,
        confidence_level=0.80
    )
    
    # Add a message
    message = db_manager.add_message(
        session_id="manager-test-456",
        role="user",
        content="I received a suspicious email",
        language="en",
        metadata={"source": "email"}
    )
    
    assert message is not None
    assert message.role == "user"
    assert message.content == "I received a suspicious email"
    assert message.language == "en"
    assert message.message_metadata == {"source": "email"}
    
    # Verify session turn count was updated
    updated_session = db_manager.get_session("manager-test-456")
    assert updated_session.total_turns == 1


def test_database_manager_complete_session(db_manager):
    """Test DatabaseManager session completion."""
    # Create a session
    session = db_manager.create_session(
        session_id="manager-test-789",
        risk_score=0.85,
        confidence_level=0.90
    )
    
    # Complete the session
    success = db_manager.complete_session(
        session_id="manager-test-789",
        engagement_duration=120
    )
    
    assert success is True
    
    # Verify session was completed
    completed_session = db_manager.get_session("manager-test-789")
    assert completed_session.status == "completed"
    assert completed_session.engagement_duration == 120
    assert completed_session.end_time is not None


def test_model_relationships(db_session):
    """Test model relationships work correctly."""
    # Create a session
    session = Session(
        session_id="relationship-test",
        risk_score=0.80,
        confidence_level=0.85
    )
    db_session.add(session)
    db_session.commit()
    
    # Create a message
    message = Message(
        session_id=session.id,
        role="user",
        content="Test message",
        language="en"
    )
    db_session.add(message)
    db_session.commit()
    
    # Create an entity
    entity = ExtractedEntity(
        session_id=session.id,
        entity_type="email",
        entity_value="test@example.com",
        confidence_score=0.90
    )
    db_session.add(entity)
    db_session.commit()
    
    # Test relationships
    assert len(session.messages) == 1
    assert len(session.entities) == 1
    assert session.messages[0].content == "Test message"
    assert session.entities[0].entity_value == "test@example.com"


def test_model_constraints(db_session):
    """Test that model constraints work correctly."""
    # Test invalid risk score (should be between 0.0 and 1.0)
    with pytest.raises(Exception):
        session = Session(
            session_id="constraint-test",
            risk_score=1.5,  # Invalid: > 1.0
            confidence_level=0.80
        )
        db_session.add(session)
        db_session.commit()
    
    # Test invalid role
    session = Session(
        session_id="constraint-test-2",
        risk_score=0.80,
        confidence_level=0.85
    )
    db_session.add(session)
    db_session.commit()
    
    with pytest.raises(Exception):
        message = Message(
            session_id=session.id,
            role="invalid_role",  # Invalid role
            content="Test message",
            language="en"
        )
        db_session.add(message)
        db_session.commit()