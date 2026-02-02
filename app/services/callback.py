import httpx
from app.core.config import settings
from app.db.models import Session, ExtractedEntity
from typing import List, Any
import logging
import asyncio

logger = logging.getLogger(__name__)

class EvaluationCallback:
    async def send_callback(self, session: Session, entities: List[ExtractedEntity], agent_notes: str = ""):
        """
        Sends the final evaluation result to the GUVI endpoint.
        Retries up to 3 times with exponential backoff.
        """
        
        # Organize entities
        extracted = {
            "bankAccounts": [],
            "upiIds": [],
            "phishingLinks": [],
            "phoneNumbers": [],
            "suspiciousKeywords": [] # Currently not persisted, would need DB schema update
        }
        
        for e in entities:
            if e.entity_type == "bank_account":
                extracted["bankAccounts"].append(e.entity_value)
            elif e.entity_type == "upi_id":
                extracted["upiIds"].append(e.entity_value)
            elif e.entity_type == "url":
                extracted["phishingLinks"].append(e.entity_value)
            elif e.entity_type == "phone":
                extracted["phoneNumbers"].append(e.entity_value)

        payload = {
            "sessionId": session.session_id,
            "scamDetected": bool(session.risk_score > 0.6), # Boolean conversion
            "totalMessagesExchanged": session.turn_count,
            "extractedIntelligence": extracted,
            "agentNotes": agent_notes or f"Auto-generated report. Risk Score: {session.risk_score}"
        }
        
        logger.info(f"Sending callback for {session.session_id}: {payload}")
        
        url = settings.EVALUATION_ENDPOINT
        retries = 3
        
        for attempt in range(retries):
            try:
                async with httpx.AsyncClient() as client:
                    resp = await client.post(url, json=payload, timeout=10.0)
                    if resp.status_code in [200, 201]:
                        logger.info(f"Callback success for {session.session_id}")
                        return True
                    else:
                        logger.warning(f"Callback failed (Attempt {attempt+1}): {resp.status_code} {resp.text}")
            except Exception as e:
                logger.error(f"Callback connection error (Attempt {attempt+1}): {e}")
            
            if attempt < retries - 1:
                await asyncio.sleep(2 ** attempt) # 1s, 2s, 4s...
        
        return False

callback_service = EvaluationCallback()
