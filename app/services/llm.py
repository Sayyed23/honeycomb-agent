import google.generativeai as genai
from app.core.config import settings
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class GeminiService:
    def __init__(self):
        self.api_key = settings.GOOGLE_API_KEY
        if not self.api_key:
            logger.warning("GOOGLE_API_KEY not set. GeminiService disabled.")
            self.model = None
        else:
            genai.configure(api_key=self.api_key)
            # Using gemini-2.0-flash as it is available for this key
            self.model = genai.GenerativeModel('gemini-2.0-flash')

    async def generate_response(
        self, 
        system_prompt: str, 
        history: List[Dict[str, str]], 
        user_input: str
    ) -> str:
        """
        Generate a response from the agent.
        
        Args:
            system_prompt: Instructions for behavior/persona.
            history: List of {"role": "user"|"model", "parts": ["text"]}
            user_input: The new message from the scammer.
            
        Returns:
            The agent's text response.
        """
        if not self.model:
            return "Error: Service not configured."

        try:
            # We will construct a chat session.
            # Strategy: Prepend system prompt to the first user message or handle it as context.
            # Since `start_chat` expects a specific history format, we need to adapt.
            
            # Simple adaptation:
            # If history is empty, the first message sent to `send_message` will just include system prompt + user input.
            # If history exists, we try to restart the chat with history.
            
            converted_history = []
            for msg in history:
                role = "user" if msg.get("role") in ["user", "scammer"] else "model"
                parts = msg.get("parts", [])
                # Ensure parts is a list of strings or convert content
                if isinstance(msg.get("content"), str):
                    parts = [msg["content"]]
                
                converted_history.append({
                    "role": role,
                    "parts": parts if isinstance(parts, list) else [str(parts)]
                })

            # Start chat with history
            chat = self.model.start_chat(history=converted_history)
            
            # Combine system prompt with user input for the immediate turn if it's effectively a new context
            # or simply prepend system prompt if history is empty.
            # If history is not empty, we can't easily inject system prompt into 'history' without messing up turns.
            # A robust way: context injection in the final prompt.
            
            full_prompt = f"{system_prompt}\n\n[INCOMING MESSAGE]: {user_input}"
            
            response = await chat.send_message_async(full_prompt)
            return response.text
            
        except Exception as e:
            logger.error(f"Gemini generation error: {e}")
            # Fallback or re-raise
            return "Error generating response."

llm_service = GeminiService()
