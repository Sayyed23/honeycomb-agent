from sqlalchemy import Column, String, Integer, Float, Boolean, Text, DateTime, ForeignKey, JSON
from sqlalchemy.orm import declarative_base, relationship
from datetime import datetime

Base = declarative_base()

class Session(Base):
    __tablename__ = "sessions"

    session_id = Column(String(255), primary_key=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    status = Column(String(50), default="ACTIVE") # ACTIVE, COMPLETED, TERMINATED_SAFETY
    risk_score = Column(Float, default=0.0)
    agent_engaged = Column(Boolean, default=False)
    persona = Column(String(50))
    turn_count = Column(Integer, default=0)
    intelligence_confidence = Column(Float, default=0.0)
    callback_sent = Column(Boolean, default=False)

    messages = relationship("Message", back_populates="session", cascade="all, delete-orphan")
    entities = relationship("ExtractedEntity", back_populates="session", cascade="all, delete-orphan")

class Message(Base):
    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(255), ForeignKey("sessions.session_id"))
    turn_number = Column(Integer)
    sender = Column(String(50)) # "scammer" or "user"
    message = Column(Text)
    timestamp = Column(DateTime) # The actual timestamp from the message
    created_at = Column(DateTime, default=datetime.utcnow) # System time

    session = relationship("Session", back_populates="messages")

class ExtractedEntity(Base):
    __tablename__ = "extracted_entities"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(255), ForeignKey("sessions.session_id"))
    entity_type = Column(String(50)) # upi_id, bank_account, phone, url
    entity_value = Column(Text)
    confidence = Column(Float)
    source_turn = Column(Integer)
    entity_metadata = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    session = relationship("Session", back_populates="entities")
