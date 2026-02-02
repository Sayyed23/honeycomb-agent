import re
from typing import List, Dict, Any
from app.services.llm import llm_service
import logging

logger = logging.getLogger(__name__)

class IntelligenceExtractor:
    # Regex Patterns
    UPI_PATTERN = r"[\w\.-]+@[\w]+"
    PHONE_PATTERN = r"(?:\+91|0)?[6-9]\d{9}"
    URL_PATTERN = r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*"
    
    # Whitelists (Simplified)
    white_listed_domains = ["google.com", "facebook.com", "whatsapp.com"]

    async def extract(self, text: str) -> List[Dict[str, Any]]:
        """
        Extracts entities from text using Regex + Optional LLM verification.
        """
        extracted = []
        
        # 1. UPI Extraction
        upis = re.findall(self.UPI_PATTERN, text)
        for upi in upis:
            # Basic validation
            if len(upi) > 3: 
                extracted.append({
                    "entity_type": "upi_id",
                    "entity_value": upi,
                    "confidence": 0.9 # Regex is usually high confidence for UPI structure
                })
        
        # 2. Phone Extraction
        phones = re.findall(self.PHONE_PATTERN, text)
        for phone in phones:
            # Clean
            clean_phone = phone.replace(" ", "").replace("-", "")
            extracted.append({
                "entity_type": "phone",
                "entity_value": clean_phone,
                "confidence": 0.85 
            })
            
        # 3. URL Extraction
        urls = re.findall(self.URL_PATTERN, text)
        for url in urls:
            # Whitelist check
            is_safe = False
            for domain in self.white_listed_domains:
                if domain in url:
                    is_safe = True
                    break
            
            if not is_safe:
                extracted.append({
                    "entity_type": "url",
                    "entity_value": url,
                    "confidence": 0.95
                })
        
        # TODO: Add LLM confirmation for ambiguous cases?
        # For now, regex is strictly following spec patterns.
        
        return extracted

    async def verify_context_with_llm(self, text: str, entity: Dict[str, Any]) -> float:
        """
        Uses LLM to confirm if the extracted entity is actually relevant in context (e.g. asking for payment vs just mentioning it).
        Returns new confidence score.
        """
        # Placeholder for deeper analysis
        return entity["confidence"]

extractor_service = IntelligenceExtractor()
