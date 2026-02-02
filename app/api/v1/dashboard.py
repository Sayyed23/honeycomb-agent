from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.db import models
from pathlib import Path

router = APIRouter()

# Locate templates directory relative to this file
# app/api/v1/dashboard.py -> app/templates
BASE_DIR = Path(__file__).resolve().parent.parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

@router.get("/session/{session_id}", response_class=HTMLResponse)
async def get_session_dashboard(request: Request, session_id: str, db: Session = Depends(get_db)):
    session = db.query(models.Session).filter(models.Session.session_id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
        
    messages = db.query(models.Message).filter(models.Message.session_id == session_id).order_by(models.Message.turn_number.asc()).all()
    entities = db.query(models.ExtractedEntity).filter(models.ExtractedEntity.session_id == session_id).all()
    
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "session": session,
        "messages": messages,
        "entities": entities
    })
