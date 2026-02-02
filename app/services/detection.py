import re
from typing import List, Dict, Any

class ScamDetector:
    # Keywords from PRD
    SCAM_KEYWORDS = {
        'urgency': ['urgent', 'immediately', 'now', 'today', 'blocked', 'suspended', 'expire'],
        'authority': ['bank', 'police', 'government', 'rbi', 'income tax', 'courier', 'official'],
        'financial': ['refund', 'cashback', 'prize', 'lottery', 'verify account', 'kyc', 'credit', 'debit', 'payment'],
        'credentials': ['otp', 'pin', 'password', 'cvv', 'card number', 'aadhaar', 'pan']
    }

    # Regex Patterns
    ENTITY_PATTERNS = {
        'upi': r'[\w\.\-]+@[\w]+',
        'phone': r'(\+91|0)?[6-9]\d{9}', # Simple Indian mobile pattern
        'url': r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+',
        'bank_account': r'\b\d{9,18}\b'
    }

    def analyze(self, message_text: str) -> Dict[str, Any]:
        """
        Analyze message text for scam indicators.
        Returns a dict with risk_score, confidence, and signals.
        """
        message_lower = message_text.lower()
        signals = []
        detected_categories = set()
        
        # 1. Keyword Analysis
        for category, keywords in self.SCAM_KEYWORDS.items():
            for keyword in keywords:
                if keyword in message_lower:
                    signals.append(f"{category}_keyword_detected: {keyword}")
                    detected_categories.add(category)
        
        # 2. Entity Analysis (Regex)
        for entity, pattern in self.ENTITY_PATTERNS.items():
            matches = re.findall(pattern, message_text)
            if matches:
                signals.append(f"{entity}_pattern_present")
                detected_categories.add('entity_present')

        # 3. Risk Scoring (Heuristic)
        risk_score = 0.0
        
        # Base score from keyword categories
        if 'urgency' in detected_categories:
            risk_score += 0.4
        if 'financial' in detected_categories:
            risk_score += 0.3
        if 'credentials' in detected_categories:
            risk_score += 0.5 # High risk
        if 'authority' in detected_categories:
            risk_score += 0.2
            
        # Modifiers
        if 'entity_present' in detected_categories and ('financial' in detected_categories or 'urgency' in detected_categories):
            risk_score += 0.3
            
        # Cap score at 1.0
        risk_score = min(risk_score, 1.0)
        
        # Determine confidence
        confidence = "low"
        if risk_score > 0.7:
            confidence = "high"
        elif risk_score > 0.4:
            confidence = "medium"

        return {
            "risk_score": round(risk_score, 2),
            "confidence": confidence,
            "signals": signals,
            "should_engage": risk_score > 0.65 # Threshold from PRD (~0.75)
        }

detector = ScamDetector()
