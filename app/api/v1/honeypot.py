from fastapi import APIRouter, Depends, HTTPException, Header, status
from sqlalchemy.orm import Session
from app.db import models
from app.db.session import get_db
from app.schemas import HoneypotRequest, HoneypotResponse
from app.services.detection import detector
from app.services.extraction import extractor_service
from app.services.agent import agent_orchestrator
from app.core.config import settings
from datetime import datetime
import logging

router = APIRouter()
logger = logging.getLogger(__name__)

# API Key Dependency (Reused/Moved)
async def verify_api_key(x_api_key: str = Header(...)):
    if x_api_key != settings.API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API Key",
        )
    return x_api_key

from fastapi import BackgroundTasks

@router.post("/message", response_model=HoneypotResponse, dependencies=[Depends(verify_api_key)])
async def handle_message(
    request: HoneypotRequest, 
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    from app.services.safety import safety_service
    from app.services.callback import callback_service

    # 1. Retrieve or Create Session
    session = db.query(models.Session).filter(models.Session.session_id == request.sessionId).first()
    
    # New Session Logic
    if not session:
        import random
        from app.core.prompts import PersonaType
        selected_persona = random.choice(list(PersonaType))
        
        session = models.Session(
            session_id=request.sessionId, 
            status="ACTIVE",
            persona=selected_persona.value,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        db.add(session)
        db.commit()

    # Check if session is already terminated
    if session.status in ["TERMINATED_SAFETY", "COMPLETED"]:
        return HoneypotResponse(status="error", reply="Session Closed.")
    
    # 2. Store Incoming Message
    incoming_msg = models.Message(
        session_id=session.session_id,
        turn_number=session.turn_count + 1,
        sender="scammer",
        message=request.message.text,
        timestamp=datetime.utcnow()
    )
    db.add(incoming_msg)
    
    # 3. Security & Scam Detection
    analysis = detector.analyze(request.message.text)
    
    session.risk_score = max(session.risk_score or 0.0, analysis["risk_score"])
    session.updated_at = datetime.utcnow()
    
    if analysis["should_engage"]:
        session.agent_engaged = True
        
    # 4. Intelligence Extraction
    extracted_data = await extractor_service.extract(request.message.text)
    for item in extracted_data:
        entity = models.ExtractedEntity(
            session_id=session.session_id,
            entity_type=item["entity_type"],
            entity_value=item["entity_value"],
            confidence=item["confidence"],
            source_turn=session.turn_count + 1
        )
        db.add(entity)
        session.intelligence_confidence = max(session.intelligence_confidence or 0.0, item["confidence"])

    # 5. Agent Response Logic
    reply_text = ""
    
    if not analysis["should_engage"] and session.risk_score < 0.6:
        reply_text = "Message received."
    else:
        history_objs = db.query(models.Message).filter(
            models.Message.session_id == session.session_id
        ).order_by(models.Message.turn_number.asc()).all()
        
        history_dicts = []
        for msg in history_objs:
             history_dicts.append({
                 "sender": msg.sender,
                 "message": msg.message
             })
        
        raw_reply = await agent_orchestrator.generate_reply(
            persona=session.persona,
            new_Message_text=request.message.text,
            history_messages=history_dicts
        )
        
        # Validate Safety
        is_safe, checked_reply = safety_service.validate_response(raw_reply)
        reply_text = checked_reply

    # 6. Store Agent Response
    agent_msg = models.Message(
        session_id=session.session_id,
        turn_number=session.turn_count + 2, 
        sender="user", 
        message=reply_text,
        timestamp=datetime.utcnow()
    )
    db.add(agent_msg)
    
    # Updates
    session.turn_count += 2
    session.updated_at = datetime.utcnow()
    
    # Termination Logic (Max Turns = 15 or 10)
    MAX_TURNS = 16 # 8 exchanges
    if session.turn_count >= MAX_TURNS:
        session.status = "COMPLETED"
        # Trigger Callback
        all_entities = db.query(models.ExtractedEntity).filter(models.ExtractedEntity.session_id == session.session_id).all()
        background_tasks.add_task(callback_service.send_callback, session, all_entities, "Max turns reached")

    db.commit()

    return HoneypotResponse(
        status="success",
        reply=reply_text
    )

@router.post("/emergency-stop/{session_id}", dependencies=[Depends(verify_api_key)])
async def emergency_stop(
    session_id: str, 
    background_tasks: BackgroundTasks, 
    db: Session = Depends(get_db)
):
    from app.services.callback import callback_service
    
    session = db.query(models.Session).filter(models.Session.session_id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
        
    session.status = "TERMINATED_SAFETY"
    db.commit()
    
    # Callback
    all_entities = db.query(models.ExtractedEntity).filter(models.ExtractedEntity.session_id == session.session_id).all()
    background_tasks.add_task(callback_service.send_callback, session, all_entities, "Emergency Stop Triggered")
    
    return {"status": "terminated", "session_id": session_id}
