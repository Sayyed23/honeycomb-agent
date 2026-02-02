from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime

# --- Request Schemas (GUVI Compliant) ---

class Message(BaseModel):
    sender: str  # "scammer" or "user"
    text: str
    timestamp: str # ISO-8601 string as per spec

class ConversationMessage(BaseModel):
    sender: str
    text: str
    timestamp: str

class Metadata(BaseModel):
    channel: str = "SMS"
    language: str = "English"
    locale: str = "IN"

class HoneypotRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: List[ConversationMessage] = []
    metadata: Optional[Metadata] = None

# --- Response Schemas ---

class HoneypotResponse(BaseModel):
    status: str = "success"
    reply: str

# --- Internal / Callback Schemas ---

class ExtractedIntelligence(BaseModel):
    bankAccounts: List[str] = []
    upiIds: List[str] = []
    phishingLinks: List[str] = []
    phoneNumbers: List[str] = []
    suspiciousKeywords: List[str] = []

class EvaluationCallbackPayload(BaseModel):
    sessionId: str
    scamDetected: bool
    totalMessagesExchanged: int
    extractedIntelligence: ExtractedIntelligence
    agentNotes: str
