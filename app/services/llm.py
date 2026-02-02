from google import genai
from google.genai import types
from app.core.config import settings
import logging
from typing import List, Dict, Any
import asyncio
import time

logger = logging.getLogger(__name__)

class GeminiService:
    def __init__(self):
        self.api_key = settings.GOOGLE_API_KEY
        if not self.api_key:
            logger.warning("GOOGLE_API_KEY not set. GeminiService disabled.")
            self.client = None
        else:
            self.client = genai.Client(api_key=self.api_key)
            self.model_name = 'gemini-2.0-flash'

    async def generate_response(
        self, 
        system_prompt: str, 
        history: List[Dict[str, str]], 
        user_input: str
    ) -> str:
        """
        Generate a response from the agent using google-genai SDK.
        Includes retry logic for 429 errors.
        """
        if not self.client:
            return "Error: Service not configured."

        # Construct content for the model
        contents = []
        
        # System instructions
        # The new SDK supports system_instruction='...' in generate_content, but we can also just prepend it.
        # Let's use the explicit argument if possible, or context injection.
        # For simplicity and robustness with chat history, we'll use config.
        
        # Convert history
        for msg in history:
            role = "user" if msg.get("role") in ["user", "scammer"] else "model"
            parts = msg.get("parts", [])
            if isinstance(msg.get("content"), str):
                parts = [msg["content"]]
            
            # parts needs to be list of text
            text_parts = parts if isinstance(parts, list) else [str(parts)]
            
            contents.append(types.Content(
                role=role,
                parts=[types.Part.from_text(text=p) for p in text_parts]
            ))
            
        # Add current user input
        contents.append(types.Content(
            role="user",
            parts=[types.Part.from_text(text=user_input)]
        ))

        config = types.GenerateContentConfig(
            system_instruction=system_prompt,
            temperature=0.7,
            candidate_count=1
        )

        # Retry Logic
        max_retries = 3
        backoff = 2 # seconds
        
        for attempt in range(max_retries + 1):
            try:
                # With google-genai 0.x/1.x (client based)
                response = self.client.models.generate_content(
                    model=self.model_name,
                    contents=contents,
                    config=config
                )
                
                if response.text:
                    return response.text
                return "Error: Empty response."

            except Exception as e:
                error_str = str(e)
                # Check for 429
                if "429" in error_str or "Resource exhausted" in error_str:
                    if attempt < max_retries:
                        sleep_time = backoff * (2 ** attempt)
                        logger.warning(f"Rate limit hit. Retrying in {sleep_time}s...")
                        await asyncio.sleep(sleep_time)
                        continue
                
                logger.error(f"Gemini generation error: {e}")
                return f"Error generating response: {e}"

        return "Error: Rate limit exceeded."

llm_service = GeminiService()
