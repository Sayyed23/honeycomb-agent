from app.services.llm import llm_service
from app.core.prompts import SYSTEM_PROMPT_TEMPLATE, PERSONA_DESCRIPTIONS, PersonaType
from typing import List, Optional
import logging

logger = logging.getLogger(__name__)

class AgentOrchestrator:
    """
    Orchestrates the agent's interaction:
    1. Selects Persona
    2. Constructs System Prompt
    3. Calls LLM Service
    """
    
    async def generate_reply(
        self, 
        persona: str, 
        new_Message_text: str, 
        history_messages: List[dict]
    ) -> str:
        """
        Args:
            persona: defined in PersonaType (digitally_naive, average_user, skeptical)
            new_Message_text: The incoming scam message
            history_messages: List of dicts e.g. [{"sender": "scammer", "message": "..."}, {"sender": "user", "message": "..."}]
        """
        
        # 1. Get Persona Description
        # Default to AVERAGE if not found
        persona_desc = PERSONA_DESCRIPTIONS.get(persona, PERSONA_DESCRIPTIONS[PersonaType.AVERAGE])
        
        # 2. Build System Prompt
        system_prompt = SYSTEM_PROMPT_TEMPLATE.format(persona_description=persona_desc)
        
        # 3. Format History
        # Map our "sender" (scammer/user) to Gemini's "user/model"
        # our 'scammer' is the user talking to the LLM.
        # our 'user' (the agent) is the model.
        formatted_history = []
        for msg in history_messages:
            sender = msg.get("sender")
            text = msg.get("message")
            
            role = "user" if sender == "scammer" else "model"
            
            formatted_history.append({
                "role": role,
                "parts": [text]
            })

        # 4. Call LLM
        response = await llm_service.generate_response(
            system_prompt=system_prompt,
            history=formatted_history,
            user_input=new_Message_text
        )
        
        return response

agent_orchestrator = AgentOrchestrator()
