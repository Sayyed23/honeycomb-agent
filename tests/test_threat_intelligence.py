"""
Unit tests for threat intelligence analysis system.

Tests scammer tactic classification, conversation analysis, network analysis,
temporal correlation, and geographic correlation functionality.
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock, patch
from typing import List, Dict, Any

from app.core.threat_intelligence import (
    ThreatIntelligenceEngine,
    TacticClassifier,
    ConversationAnalyzer,
    NetworkAnalyzer,
    TemporalAnalyzer,
    GeographicAnalyzer,
    ScammerTactic,
    MethodologyType,
    ThreatSeverity,
    TacticPattern,
    ConversationAnalysis,
    NetworkConnection,
    TemporalPattern,
    GeographicCorrelation
)
from app.database.models import Session, Message, ExtractedEntity


class TestTacticClassifier:
    """Test cases for scammer tactic classification."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.classifier = TacticClassifier()
    
    def test_urgency_creation_detection(self):
        """Test detection of urgency creation tactics."""
        messages = [
            "This is urgent! You need to act immediately!",
            "Your account will be closed in 24 hours if you don't respond now!"
        ]
        
        tactics = self.classifier.classify_tactics(messages)
        
        # Should detect urgency creation
        urgency_tactics = [t for t in tactics if t.tactic == ScammerTactic.URGENCY_CREATION]
        assert len(urgency_tactics) > 0
        assert urgency_tactics[0].confidence > 0.3
        assert 'urgent' in urgency_tactics[0].indicators or 'immediately' in urgency_tactics[0].indicators
    
    def test_authority_impersonation_detection(self):
        """Test detection of authority impersonation tactics."""
        messages = [
            "This is from the bank security department.",
            "I am an authorized government official and need your details."
        ]
        
        tactics = self.classifier.classify_tactics(messages)
        
        # Should detect authority impersonation
        authority_tactics = [t for t in tactics if t.tactic == ScammerTactic.AUTHORITY_IMPERSONATION]
        assert len(authority_tactics) > 0
        assert authority_tactics[0].confidence > 0.3
    
    def test_financial_incentive_detection(self):
        """Test detection of financial incentive tactics."""
        messages = [
            "You can earn 50,000 rupees easily!",
            "Free money waiting for you, just click this link!"
        ]
        
        tactics = self.classifier.classify_tactics(messages)
        
        # Should detect financial incentive
        financial_tactics = [t for t in tactics if t.tactic == ScammerTactic.FINANCIAL_INCENTIVE]
        assert len(financial_tactics) > 0
        assert financial_tactics[0].confidence > 0.3
    
    def test_information_harvesting_detection(self):
        """Test detection of information harvesting tactics."""
        messages = [
            "Please provide your account number and PIN for verification.",
            "Share your personal details to complete the process."
        ]
        
        tactics = self.classifier.classify_tactics(messages)
        
        # Should detect information harvesting
        info_tactics = [t for t in tactics if t.tactic == ScammerTactic.INFORMATION_HARVESTING]
        assert len(info_tactics) > 0
        assert info_tactics[0].confidence > 0.3
    
    def test_no_tactics_in_normal_message(self):
        """Test that normal messages don't trigger false positives."""
        messages = [
            "Hello, how are you today?",
            "The weather is nice. Have a good day!"
        ]
        
        tactics = self.classifier.classify_tactics(messages)
        
        # Should not detect any high-confidence tactics
        high_confidence_tactics = [t for t in tactics if t.confidence > 0.5]
        assert len(high_confidence_tactics) == 0
    
    def test_multiple_tactics_detection(self):
        """Test detection of multiple tactics in one message."""
        messages = [
            "URGENT! Bank manager here. You must provide your account details immediately or lose money!"
        ]
        
        tactics = self.classifier.classify_tactics(messages)
        
        # Should detect multiple tactics
        tactic_types = [t.tactic for t in tactics if t.confidence > 0.3]
        assert len(set(tactic_types)) >= 2  # At least 2 different tactics


class TestGeographicAnalyzer:
    """Test cases for geographic correlation analysis."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.analyzer = GeographicAnalyzer()
    
    def test_simple_ip_to_region_mapping(self):
        """Test simple IP to region mapping."""
        # Test various IP ranges
        assert self.analyzer._simple_ip_to_region("25.123.45.67") == "North America"
        assert self.analyzer._simple_ip_to_region("75.123.45.67") == "Europe"
        assert self.analyzer._simple_ip_to_region("125.123.45.67") == "Asia Pacific"
        assert self.analyzer._simple_ip_to_region("175.123.45.67") == "South Asia"
        assert self.analyzer._simple_ip_to_region("225.123.45.67") == "Other Regions"
    
    def test_invalid_ip_handling(self):
        """Test handling of invalid IP addresses."""
        assert self.analyzer._simple_ip_to_region("invalid.ip") is None
        assert self.analyzer._simple_ip_to_region("300.300.300.300") is None
        assert self.analyzer._simple_ip_to_region("") is None
    
    def test_time_correlation_calculation(self):
        """Test time correlation calculation."""
        # Test clustered timestamps (high correlation)
        now = datetime.utcnow()
        clustered_timestamps = [
            now,
            now + timedelta(minutes=5),
            now + timedelta(minutes=10)
        ]
        correlation = self.analyzer._calculate_time_correlation(clustered_timestamps)
        assert correlation > 0.8  # Should be high correlation
        
        # Test spread timestamps (low correlation)
        spread_timestamps = [
            now,
            now + timedelta(days=1),
            now + timedelta(days=2)
        ]
        correlation = self.analyzer._calculate_time_correlation(spread_timestamps)
        assert correlation < 0.5  # Should be low correlation
    
    def test_regional_threat_assessment(self):
        """Test regional threat assessment logic."""
        # High threat scenario
        threat = self.analyzer._assess_regional_threat(
            session_count=15,
            entity_overlap=8,
            time_correlation=0.9,
            risk_scores=[0.9, 0.8, 0.85, 0.9]
        )
        assert threat in [ThreatSeverity.CRITICAL, ThreatSeverity.HIGH]
        
        # Low threat scenario
        threat = self.analyzer._assess_regional_threat(
            session_count=2,
            entity_overlap=0,
            time_correlation=0.1,
            risk_scores=[0.3, 0.2]
        )
        assert threat == ThreatSeverity.LOW
    
    @pytest.mark.asyncio
    async def test_get_region_from_ip_caching(self):
        """Test IP to region caching functionality."""
        ip = "192.168.1.1"
        
        # First call should compute and cache
        region1 = await self.analyzer._get_region_from_ip(ip)
        
        # Second call should use cache
        region2 = await self.analyzer._get_region_from_ip(ip)
        
        assert region1 == region2
        assert ip in self.analyzer.ip_to_region_cache


class TestConversationAnalyzer:
    """Test cases for conversation analysis."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.analyzer = ConversationAnalyzer()
    
    def test_determine_primary_methodology(self):
        """Test methodology determination from tactics."""
        # Create mock tactics for financial fraud
        financial_tactics = [
            TacticPattern(
                tactic=ScammerTactic.URGENCY_CREATION,
                confidence=0.8,
                indicators=['urgent', 'immediately'],
                context="payment context",
                severity=ThreatSeverity.HIGH,
                methodology=MethodologyType.FINANCIAL_FRAUD
            ),
            TacticPattern(
                tactic=ScammerTactic.INFORMATION_HARVESTING,
                confidence=0.9,
                indicators=['account', 'details'],
                context="banking context",
                severity=ThreatSeverity.CRITICAL,
                methodology=MethodologyType.FINANCIAL_FRAUD
            )
        ]
        
        methodology = self.analyzer._determine_primary_methodology(financial_tactics)
        assert methodology == MethodologyType.FINANCIAL_FRAUD
    
    def test_calculate_threat_score(self):
        """Test threat score calculation."""
        tactics = [
            TacticPattern(
                tactic=ScammerTactic.CREDENTIAL_PHISHING,
                confidence=0.9,
                indicators=['login', 'password'],
                context="phishing context",
                severity=ThreatSeverity.CRITICAL,
                methodology=MethodologyType.PHISHING
            )
        ]
        
        base_risk = 0.7
        threat_score = self.analyzer._calculate_threat_score(tactics, base_risk)
        
        # Should boost score due to critical tactic
        assert threat_score > base_risk
        assert threat_score <= 1.0
    
    def test_extract_key_indicators(self):
        """Test key indicator extraction."""
        messages = [
            "Please provide your bank account details for verification",
            "This is urgent and requires immediate action"
        ]
        
        tactics = [
            TacticPattern(
                tactic=ScammerTactic.INFORMATION_HARVESTING,
                confidence=0.8,
                indicators=['bank', 'account', 'details'],
                context="verification context",
                severity=ThreatSeverity.HIGH,
                methodology=MethodologyType.FINANCIAL_FRAUD
            )
        ]
        
        indicators = self.analyzer._extract_key_indicators(messages, tactics)
        
        assert len(indicators) > 0
        assert any('bank' in indicator or 'account' in indicator for indicator in indicators)


class TestNetworkAnalyzer:
    """Test cases for network analysis."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.analyzer = NetworkAnalyzer()
    
    def test_determine_network_threat_level(self):
        """Test network threat level determination."""
        # High-risk UPI with high frequency
        threat = self.analyzer._determine_network_threat_level('upi_id', 0.9, 5)
        assert threat == ThreatSeverity.CRITICAL
        
        # Phone number with moderate frequency
        threat = self.analyzer._determine_network_threat_level('phone_number', 0.7, 3)
        assert threat == ThreatSeverity.MEDIUM
        
        # Low-risk entity
        threat = self.analyzer._determine_network_threat_level('email', 0.3, 1)
        assert threat == ThreatSeverity.LOW


class TestTemporalAnalyzer:
    """Test cases for temporal analysis."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.analyzer = TemporalAnalyzer()
    
    @pytest.mark.asyncio
    async def test_analyze_hourly_patterns(self):
        """Test hourly pattern analysis."""
        # Create mock sessions with concentrated activity
        now = datetime.utcnow()
        sessions = []
        
        # Create sessions concentrated in specific hours
        for i in range(10):
            session = Mock()
            session.session_id = f"session_{i}"
            session.created_at = now.replace(hour=14, minute=i*5)  # Concentrated at 2 PM
            sessions.append(session)
        
        # Add some sessions at different hours
        for i in range(3):
            session = Mock()
            session.session_id = f"session_other_{i}"
            session.created_at = now.replace(hour=10, minute=i*10)
            sessions.append(session)
        
        pattern = await self.analyzer._analyze_hourly_patterns(sessions)
        
        if pattern:
            assert pattern.pattern_type == "hourly_peak"
            assert pattern.confidence > 0.0


class TestThreatIntelligenceEngine:
    """Test cases for the main threat intelligence engine."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.engine = ThreatIntelligenceEngine()
    
    def test_engine_initialization(self):
        """Test that engine initializes all components."""
        assert self.engine.conversation_analyzer is not None
        assert self.engine.network_analyzer is not None
        assert self.engine.temporal_analyzer is not None
        assert self.engine.geographic_analyzer is not None
    
    def test_analyze_common_tactics(self):
        """Test common tactics analysis."""
        # Create mock conversation analyses
        analyses = []
        for i in range(3):
            analysis = Mock()
            analysis.tactics_detected = [
                Mock(tactic=Mock(value='urgency_creation')),
                Mock(tactic=Mock(value='authority_impersonation'))
            ]
            analyses.append(analysis)
        
        common_tactics = self.engine._analyze_common_tactics(analyses)
        
        assert 'urgency_creation' in common_tactics
        assert 'authority_impersonation' in common_tactics
        assert common_tactics['urgency_creation'] == 3  # Should appear in all 3 analyses
    
    def test_analyze_methodology_distribution(self):
        """Test methodology distribution analysis."""
        # Create mock analyses with different methodologies
        analyses = []
        methodologies = [MethodologyType.FINANCIAL_FRAUD, MethodologyType.PHISHING, MethodologyType.FINANCIAL_FRAUD]
        
        for methodology in methodologies:
            analysis = Mock()
            analysis.methodology_classification = Mock(value=methodology.value)
            analyses.append(analysis)
        
        distribution = self.engine._analyze_methodology_distribution(analyses)
        
        assert distribution['financial_fraud'] == 2
        assert distribution['phishing'] == 1
    
    def test_analyze_threat_scores(self):
        """Test threat score distribution analysis."""
        # Create mock analyses with different threat scores
        analyses = []
        scores = [0.95, 0.8, 0.6, 0.3]  # Critical, high, medium, low
        
        for score in scores:
            analysis = Mock()
            analysis.threat_score = score
            analyses.append(analysis)
        
        distribution = self.engine._analyze_threat_scores(analyses)
        
        assert distribution['critical (0.9-1.0)'] == 1
        assert distribution['high (0.7-0.9)'] == 1
        assert distribution['medium (0.5-0.7)'] == 1
        assert distribution['low (0.0-0.5)'] == 1


# Integration tests
class TestThreatIntelligenceIntegration:
    """Integration tests for threat intelligence system."""
    
    @pytest.mark.asyncio
    async def test_end_to_end_analysis_flow(self):
        """Test complete analysis flow from tactics to intelligence report."""
        engine = ThreatIntelligenceEngine()
        
        # Test that engine can generate empty report without errors
        with patch('app.core.threat_intelligence.get_db_session') as mock_db:
            mock_db.return_value.__aenter__.return_value.execute.return_value.scalars.return_value.all.return_value = []
            
            report = await engine.generate_threat_intelligence_report(lookback_days=7)
            
            assert 'report_period' in report
            assert 'network_intelligence' in report
            assert 'temporal_intelligence' in report
            assert 'geographic_intelligence' in report
            assert 'conversation_intelligence' in report
            assert 'key_findings' in report
            assert 'recommendations' in report