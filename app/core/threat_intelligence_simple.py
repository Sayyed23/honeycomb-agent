"""
Simplified threat intelligence engine for scam detection.
Provides basic threat analysis without complex database operations.
"""

from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
import json

from app.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class ThreatIntelligenceReport:
    """Threat intelligence analysis report."""
    session_id: str
    threat_level: str
    confidence_score: float
    indicators: List[str]
    recommendations: List[str]
    analysis_timestamp: datetime
    metadata: Dict[str, Any]


class ThreatLevel(Enum):
    """Threat level classifications."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SimpleThreatIntelligenceEngine:
    """
    Simplified threat intelligence engine that provides basic analysis
    without complex database dependencies.
    """
    
    def __init__(self):
        """Initialize the threat intelligence engine."""
        self.threat_indicators = {
            'financial_keywords': ['money', 'payment', 'bank', 'account', 'upi', 'transfer'],
            'urgency_keywords': ['urgent', 'immediately', 'asap', 'emergency', 'quick'],
            'authority_keywords': ['officer', 'manager', 'police', 'government', 'official'],
            'fear_keywords': ['blocked', 'suspended', 'penalty', 'fine', 'arrest'],
            'trust_keywords': ['trust', 'honest', 'genuine', 'verified', 'authorized']
        }
        
        logger.info("Initialized simplified threat intelligence engine")
    
    async def analyze_conversation(self, session_id: str, context: Dict[str, Any] = None) -> ThreatIntelligenceReport:
        """
        Analyze conversation for threat indicators.
        
        Args:
            session_id: Session identifier
            context: Additional context for analysis
            
        Returns:
            ThreatIntelligenceReport: Analysis report
        """
        try:
            logger.info(f"Analyzing conversation for session {session_id}")
            
            # Basic threat analysis based on context
            threat_level = ThreatLevel.LOW
            confidence_score = 0.3
            indicators = []
            recommendations = []
            
            if context:
                message_text = context.get('message', '').lower()
                
                # Check for threat indicators
                for category, keywords in self.threat_indicators.items():
                    found_keywords = [kw for kw in keywords if kw in message_text]
                    if found_keywords:
                        indicators.append(f"{category}: {', '.join(found_keywords)}")
                        confidence_score += 0.1 * len(found_keywords)
                
                # Determine threat level based on indicators
                if len(indicators) >= 3:
                    threat_level = ThreatLevel.HIGH
                    confidence_score = min(confidence_score, 0.9)
                elif len(indicators) >= 2:
                    threat_level = ThreatLevel.MEDIUM
                    confidence_score = min(confidence_score, 0.7)
                else:
                    threat_level = ThreatLevel.LOW
                    confidence_score = min(confidence_score, 0.5)
                
                # Generate recommendations
                if threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
                    recommendations.extend([
                        "High threat detected - engage with caution",
                        "Collect additional information for verification",
                        "Monitor for escalation patterns"
                    ])
                elif threat_level == ThreatLevel.MEDIUM:
                    recommendations.extend([
                        "Moderate threat - maintain vigilance",
                        "Look for additional confirmation signals"
                    ])
                else:
                    recommendations.append("Low threat - standard engagement protocols")
            
            return ThreatIntelligenceReport(
                session_id=session_id,
                threat_level=threat_level.value,
                confidence_score=confidence_score,
                indicators=indicators,
                recommendations=recommendations,
                analysis_timestamp=datetime.utcnow(),
                metadata={
                    'analysis_method': 'simplified_keyword_analysis',
                    'context_available': bool(context)
                }
            )
            
        except Exception as e:
            logger.error(f"Error in threat analysis: {e}", exc_info=True)
            
            # Return safe default report
            return ThreatIntelligenceReport(
                session_id=session_id,
                threat_level=ThreatLevel.LOW.value,
                confidence_score=0.1,
                indicators=[],
                recommendations=["Analysis failed - use default protocols"],
                analysis_timestamp=datetime.utcnow(),
                metadata={'error': str(e)}
            )
    
    async def get_entity_patterns(self, lookback_days: int = 7) -> Dict[str, Any]:
        """
        Get entity patterns from recent data.
        
        Args:
            lookback_days: Number of days to look back
            
        Returns:
            Dict[str, Any]: Entity patterns analysis
        """
        logger.info(f"Getting entity patterns for last {lookback_days} days")
        
        # Mock entity patterns for now
        return {
            'phone_numbers': {
                'count': 5,
                'unique_count': 3,
                'most_common': '+91XXXXXXXXXX'
            },
            'upi_ids': {
                'count': 2,
                'unique_count': 2,
                'most_common': 'scammer@paytm'
            },
            'bank_accounts': {
                'count': 1,
                'unique_count': 1,
                'most_common': 'XXXX1234'
            }
        }
    
    async def get_ip_analysis(self, lookback_days: int = 7) -> Dict[str, Any]:
        """
        Get IP address analysis.
        
        Args:
            lookback_days: Number of days to look back
            
        Returns:
            Dict[str, Any]: IP analysis results
        """
        logger.info(f"Getting IP analysis for last {lookback_days} days")
        
        # Mock IP analysis for now
        return {
            'unique_ips': 10,
            'suspicious_ips': 2,
            'geographic_distribution': {
                'India': 8,
                'Unknown': 2
            },
            'risk_assessment': 'medium'
        }
    
    async def get_behavioral_patterns(self, lookback_days: int = 7) -> Dict[str, Any]:
        """
        Get behavioral patterns analysis.
        
        Args:
            lookback_days: Number of days to look back
            
        Returns:
            Dict[str, Any]: Behavioral patterns
        """
        logger.info(f"Getting behavioral patterns for last {lookback_days} days")
        
        # Mock behavioral patterns for now
        return {
            'high_risk_sessions': 5,
            'average_risk_score': 0.65,
            'common_tactics': [
                'urgency_creation',
                'authority_impersonation',
                'financial_requests'
            ],
            'time_patterns': {
                'peak_hours': '10:00-16:00',
                'peak_days': 'weekdays'
            }
        }
    
    async def get_campaign_analysis(self, lookback_days: int = 30) -> Dict[str, Any]:
        """
        Get campaign analysis.
        
        Args:
            lookback_days: Number of days to look back
            
        Returns:
            Dict[str, Any]: Campaign analysis
        """
        logger.info(f"Getting campaign analysis for last {lookback_days} days")
        
        # Mock campaign analysis for now
        return {
            'identified_campaigns': 2,
            'campaign_details': [
                {
                    'name': 'Bank Account Verification Scam',
                    'sessions': 15,
                    'success_rate': 0.2,
                    'tactics': ['authority_impersonation', 'urgency']
                },
                {
                    'name': 'UPI Prize Winner Scam',
                    'sessions': 8,
                    'success_rate': 0.15,
                    'tactics': ['fake_rewards', 'financial_requests']
                }
            ]
        }


# Global instance
threat_intelligence_engine = SimpleThreatIntelligenceEngine()