"""
Simplified ML-based scam classification system.
Uses rule-based detection when scikit-learn is not available.
"""

import re
import json
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from pathlib import Path

from app.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class MLPrediction:
    """ML model prediction result."""
    probability: float
    confidence: float
    model_predictions: Dict[str, float]
    feature_importance: Dict[str, float]
    preprocessing_info: Dict[str, Any]


class SimpleScamDetector:
    """
    Simplified rule-based scam detector that mimics ML behavior.
    Used when scikit-learn is not available.
    """
    
    def __init__(self):
        """Initialize simple scam detector."""
        self.scam_keywords = {
            'urgency': ['urgent', 'immediately', 'asap', 'emergency', 'quick', 'fast', 'hurry', 'turant', 'jaldi'],
            'financial': ['money', 'payment', 'bank', 'account', 'upi', 'transfer', 'cash', 'paisa', 'rupees'],
            'trust': ['trust', 'honest', 'genuine', 'official', 'authorized', 'verified', 'bharosa'],
            'authority': ['officer', 'manager', 'executive', 'representative', 'agent', 'police'],
            'fear': ['blocked', 'suspended', 'cancelled', 'penalty', 'fine', 'legal', 'arrest'],
            'rewards': ['won', 'winner', 'prize', 'lottery', 'congratulations', 'selected', 'lucky'],
            'requests': ['send', 'share', 'give', 'provide', 'bhejo', 'do']
        }
        
        self.suspicious_patterns = [
            r'\b(?:\+91|91)?[6-9]\d{9}\b',  # Phone numbers
            r'\b\w+@(?:paytm|phonepe|googlepay|okaxis|ybl|ibl|axl)\b',  # UPI IDs
            r'otp|cvv|pin|password',  # Sensitive info requests
            r'bank.*(?:details|number|account)',  # Bank info requests
        ]
    
    def calculate_risk_score(self, text: str) -> Tuple[float, float]:
        """
        Calculate risk score based on keywords and patterns.
        
        Args:
            text: Text to analyze
            
        Returns:
            Tuple[float, float]: (risk_score, confidence)
        """
        if not text:
            return 0.1, 0.3
        
        text_lower = text.lower()
        total_score = 0.0
        
        # Check keyword categories
        for category, keywords in self.scam_keywords.items():
            category_score = sum(1 for keyword in keywords if keyword in text_lower)
            
            # Weight different categories
            if category == 'urgency':
                total_score += category_score * 0.3
            elif category == 'financial':
                total_score += category_score * 0.25
            elif category == 'fear':
                total_score += category_score * 0.2
            elif category == 'requests':
                total_score += category_score * 0.15
            else:
                total_score += category_score * 0.1
        
        # Check suspicious patterns
        pattern_score = sum(1 for pattern in self.suspicious_patterns if re.search(pattern, text_lower))
        total_score += pattern_score * 0.4
        
        # Check for excessive punctuation
        exclamation_count = text.count('!')
        question_count = text.count('?')
        if exclamation_count > 2 or question_count > 2:
            total_score += 0.3
        
        # Check for caps ratio
        if text:
            caps_ratio = sum(1 for c in text if c.isupper()) / len(text)
            if caps_ratio > 0.3:
                total_score += 0.2
        
        # Normalize score to [0, 1]
        risk_score = min(total_score / 5.0, 1.0)
        
        # Calculate confidence based on number of indicators
        confidence = min(total_score / 3.0, 1.0)
        
        return risk_score, confidence
    
    def predict(self, text: str, conversation_history: List[str] = None) -> MLPrediction:
        """
        Predict if text is a scam using rule-based approach.
        
        Args:
            text: Text to analyze
            conversation_history: Previous conversation messages
            
        Returns:
            MLPrediction: Prediction result
        """
        # Analyze main text
        risk_score, confidence = self.calculate_risk_score(text)
        
        # Consider conversation history
        if conversation_history:
            context_scores = []
            for msg in conversation_history[-3:]:  # Last 3 messages
                ctx_score, _ = self.calculate_risk_score(msg)
                context_scores.append(ctx_score)
            
            if context_scores:
                avg_context_score = sum(context_scores) / len(context_scores)
                # Blend current and context scores
                risk_score = 0.7 * risk_score + 0.3 * avg_context_score
        
        # Create mock model predictions
        model_predictions = {
            'rule_based': risk_score,
            'keyword_matcher': risk_score * 0.9,
            'pattern_detector': risk_score * 1.1
        }
        
        # Create mock feature importance
        feature_importance = {
            'urgency_keywords': 0.3,
            'financial_keywords': 0.25,
            'suspicious_patterns': 0.2,
            'fear_tactics': 0.15,
            'text_structure': 0.1
        }
        
        # Preprocessing info
        preprocessing_info = {
            'original_text': text,
            'text_length': len(text),
            'word_count': len(text.split()),
            'has_phone': bool(re.search(r'\b(?:\+91|91)?[6-9]\d{9}\b', text)),
            'has_upi': bool(re.search(r'\b\w+@(?:paytm|phonepe|googlepay|okaxis|ybl|ibl|axl)\b', text.lower())),
        }
        
        return MLPrediction(
            probability=risk_score,
            confidence=confidence,
            model_predictions=model_predictions,
            feature_importance=feature_importance,
            preprocessing_info=preprocessing_info
        )


class MLScamDetector:
    """
    ML-based scam detection system with fallback to rule-based detection.
    """
    
    def __init__(self, model_path: Optional[str] = None):
        """
        Initialize ML scam detector.
        
        Args:
            model_path: Path to saved model files (unused in simplified version)
        """
        self.detector = SimpleScamDetector()
        self.is_trained = True  # Always ready with rule-based approach
        
        logger.info("Initialized simplified scam detector (rule-based)")
    
    def predict(self, text: str, conversation_history: List[str] = None) -> MLPrediction:
        """
        Predict if text is a scam.
        
        Args:
            text: Text to analyze
            conversation_history: Previous conversation messages
            
        Returns:
            MLPrediction: Prediction result
        """
        return self.detector.predict(text, conversation_history)
    
    def train_with_synthetic_data(self) -> Dict[str, Any]:
        """
        Mock training method for compatibility.
        
        Returns:
            Dict[str, Any]: Mock training results
        """
        return {
            'train_metrics': {'accuracy': 0.85},
            'test_metrics': {'accuracy': 0.82},
            'feature_count': 100,
            'training_samples': 200,
            'method': 'rule_based'
        }