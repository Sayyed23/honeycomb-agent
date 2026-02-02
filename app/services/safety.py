import re
from typing import Tuple

class SafetyService:
    # Basic PII patterns to catch accidental leakage
    AADHAAR_PATTERN = r"\b\d{4}\s\d{4}\s\d{4}\b"
    PAN_PATTERN = r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b"
    
    def validate_response(self, text: str) -> Tuple[bool, str]:
        """
        Validates the agent's generated response.
        Returns (is_safe, refined_text_or_reason).
        """
        # 1. PII Check
        if re.search(self.AADHAAR_PATTERN, text):
            return False, "Response contains potential Aadhaar number."
        if re.search(self.PAN_PATTERN, text):
            return False, "Response contains potential PAN number."
            
        # 2. Length Check (Agent shouldn't ramble)
        if len(text) > 400:
             return True, text[:400] + "..." # Truncate if too long?
             
        # 3. Empty check
        if not text.strip():
            return False, "Empty response generated."
            
        return True, text

safety_service = SafetyService()
