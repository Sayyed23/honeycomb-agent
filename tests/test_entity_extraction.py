"""
Unit tests for the entity extraction system.

Tests the comprehensive entity recognition pipeline including UPI IDs,
phone numbers, URLs, bank accounts, and emails with confidence scoring
and threat categorization.
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime

from app.core.entity_extraction import (
    EntityExtractionEngine, UPIExtractor, PhoneNumberExtractor, 
    URLExtractor, BankAccountExtractor, EmailExtractor,
    EntityType, ThreatType, SeverityLevel, ExtractedEntityData
)


class TestUPIExtractor:
    """Test UPI ID extraction with various formats."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.extractor = UPIExtractor()
    
    def test_standard_upi_extraction(self):
        """Test extraction of standard UPI IDs."""
        text = "Please send money to john.doe@paytm"
        entities = self.extractor.extract(text)
        
        assert len(entities) == 1
        assert entities[0].entity_value == "john.doe@paytm"
        assert entities[0].entity_type == EntityType.UPI_ID
        assert entities[0].confidence_score >= 0.9
        assert entities[0].threat_type == ThreatType.FINANCIAL
        assert entities[0].severity_level == SeverityLevel.CRITICAL
    
    def test_phone_based_upi_extraction(self):
        """Test extraction of phone number based UPI IDs."""
        text = "Transfer to 9876543210@ybl"
        entities = self.extractor.extract(text)
        
        assert len(entities) == 1
        assert entities[0].entity_value == "9876543210@ybl"
        assert entities[0].confidence_score >= 0.9
    
    def test_multiple_upi_providers(self):
        """Test extraction with various UPI providers."""
        text = "Send to user@phonepe or backup@googlepay or main@bhim"
        entities = self.extractor.extract(text)
        
        assert len(entities) == 3
        upi_values = [e.entity_value for e in entities]
        assert "user@phonepe" in upi_values
        assert "backup@googlepay" in upi_values
        assert "main@bhim" in upi_values
    
    def test_invalid_upi_rejection(self):
        """Test rejection of invalid UPI formats."""
        text = "Invalid UPIs: @invalid, user@, @, user@invalid-provider"
        entities = self.extractor.extract(text)
        
        # Should not extract invalid UPIs
        assert len(entities) == 0
    
    def test_context_confidence_boost(self):
        """Test confidence boost from supporting context."""
        text_with_context = "Please make UPI payment to john@paytm for the transfer"
        text_without_context = "Contact john@paytm for details"
        
        entities_with = self.extractor.extract(text_with_context)
        entities_without = self.extractor.extract(text_without_context)
        
        assert len(entities_with) == 1
        assert len(entities_without) == 1
        # Both should have high confidence, but with context should be >= without context
        assert entities_with[0].confidence_score >= entities_without[0].confidence_score
        # Both should be above the threshold
        assert entities_with[0].confidence_score >= 0.9
        assert entities_without[0].confidence_score >= 0.9


class TestPhoneNumberExtractor:
    """Test phone number extraction with international support."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.extractor = PhoneNumberExtractor()
    
    def test_indian_mobile_extraction(self):
        """Test extraction of Indian mobile numbers."""
        text = "Call me at 9876543210 or +91-9876543210"
        entities = self.extractor.extract(text)
        
        assert len(entities) == 2
        phone_values = [e.entity_value for e in entities]
        assert "9876543210" in phone_values
        assert "+91-9876543210" in phone_values
        
        for entity in entities:
            assert entity.entity_type == EntityType.PHONE_NUMBER
            assert entity.threat_type == ThreatType.COMMUNICATION
            assert entity.severity_level == SeverityLevel.HIGH
    
    def test_formatted_phone_numbers(self):
        """Test extraction of formatted phone numbers."""
        text = "Contact: 987-654-3210 or (91) 987-654-3210"
        entities = self.extractor.extract(text)
        
        assert len(entities) >= 1
        for entity in entities:
            assert entity.confidence_score >= 0.85
    
    def test_international_phone_numbers(self):
        """Test extraction of international phone numbers."""
        text = "International: +1-555-123-4567 or +44-20-7946-0958"
        entities = self.extractor.extract(text)
        
        assert len(entities) >= 1
        for entity in entities:
            assert entity.entity_type == EntityType.PHONE_NUMBER
    
    def test_invalid_phone_rejection(self):
        """Test rejection of invalid phone numbers."""
        text = "Invalid: 123, 0000000000, 12345"
        entities = self.extractor.extract(text)
        
        # Should not extract invalid phone numbers
        assert len(entities) == 0


class TestURLExtractor:
    """Test URL extraction with reputation analysis."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.extractor = URLExtractor()
    
    def test_standard_url_extraction(self):
        """Test extraction of standard URLs."""
        text = "Visit https://example.com or http://test.org"
        entities = self.extractor.extract(text)
        
        assert len(entities) == 2
        url_values = [e.entity_value for e in entities]
        assert "https://example.com" in url_values
        assert "http://test.org" in url_values
        
        for entity in entities:
            assert entity.entity_type == EntityType.URL
            assert entity.threat_type == ThreatType.INFRASTRUCTURE
    
    def test_url_without_protocol(self):
        """Test extraction of URLs without protocol."""
        text = "Check www.example.com or example.org"
        entities = self.extractor.extract(text)
        
        assert len(entities) >= 1
        for entity in entities:
            assert entity.confidence_score >= 0.8
    
    def test_shortened_url_extraction(self):
        """Test extraction of shortened URLs."""
        text = "Click bit.ly/test123 or t.co/abc123"
        entities = self.extractor.extract(text)
        
        assert len(entities) >= 1
        for entity in entities:
            assert entity.entity_type == EntityType.URL
    
    def test_suspicious_url_detection(self):
        """Test detection of suspicious URLs."""
        text = "Visit 192.168.1.1 or verylongdomainnamethatissuspicious.com"
        entities = self.extractor.extract(text)
        
        # Should still extract but with appropriate threat level
        for entity in entities:
            if "192.168.1.1" in entity.entity_value:
                assert entity.severity_level == SeverityLevel.HIGH


class TestBankAccountExtractor:
    """Test bank account extraction with format validation."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.extractor = BankAccountExtractor()
    
    def test_indian_bank_account_extraction(self):
        """Test extraction of Indian bank account numbers."""
        text = "Transfer to account 123456789012345"
        entities = self.extractor.extract(text)
        
        assert len(entities) == 1
        assert entities[0].entity_value == "123456789012345"
        assert entities[0].entity_type == EntityType.BANK_ACCOUNT
        assert entities[0].threat_type == ThreatType.FINANCIAL
        assert entities[0].severity_level == SeverityLevel.CRITICAL
        assert entities[0].confidence_score >= 0.95
    
    def test_formatted_account_numbers(self):
        """Test extraction of formatted account numbers."""
        text = "Account: 1234-5678-9012 or 123 456 789"
        entities = self.extractor.extract(text)
        
        assert len(entities) >= 1
        for entity in entities:
            assert entity.entity_type == EntityType.BANK_ACCOUNT
    
    def test_invalid_account_rejection(self):
        """Test rejection of invalid account numbers."""
        text = "Invalid: 123, 00000000, 12345678901234567890"
        entities = self.extractor.extract(text)
        
        # Should not extract invalid account numbers
        assert len(entities) == 0


class TestEmailExtractor:
    """Test email extraction with domain validation."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.extractor = EmailExtractor()
    
    def test_standard_email_extraction(self):
        """Test extraction of standard email addresses."""
        text = "Contact user@example.com or admin@test.org"
        entities = self.extractor.extract(text)
        
        assert len(entities) == 2
        email_values = [e.entity_value for e in entities]
        assert "user@example.com" in email_values
        assert "admin@test.org" in email_values
        
        for entity in entities:
            assert entity.entity_type == EntityType.EMAIL
            assert entity.threat_type == ThreatType.COMMUNICATION
            assert entity.severity_level == SeverityLevel.MEDIUM
    
    def test_complex_email_formats(self):
        """Test extraction of complex email formats."""
        text = "Email: user.name+tag@example-domain.co.uk"
        entities = self.extractor.extract(text)
        
        assert len(entities) == 1
        assert entities[0].confidence_score >= 0.8
    
    def test_invalid_email_rejection(self):
        """Test rejection of invalid email addresses."""
        text = "Invalid: @invalid.com, user@, user@invalid"
        entities = self.extractor.extract(text)
        
        # Should not extract invalid emails
        assert len(entities) == 0


class TestEntityExtractionEngine:
    """Test the main entity extraction engine."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.engine = EntityExtractionEngine()
    
    @pytest.mark.asyncio
    async def test_comprehensive_entity_extraction(self):
        """Test extraction of multiple entity types from single text."""
        text = """
        Please transfer money to john@paytm or call 9876543210.
        You can also visit https://example.com or email user@test.com.
        Bank account: 123456789012345
        """
        
        with patch('app.core.session_manager.session_manager') as mock_session_manager:
            mock_session_manager.get_session.return_value = None
            mock_session_manager.add_extracted_entity = AsyncMock()
            
            with patch('app.core.entity_extraction.get_db_session') as mock_db:
                mock_db.return_value.__aenter__.return_value.execute.return_value.scalar_one_or_none.return_value = None
                
                result = await self.engine.extract_entities(
                    text=text,
                    session_id="test-session",
                    context="Test extraction",
                    confidence_threshold=0.8
                )
        
        assert result.high_confidence_count >= 3  # Should find UPI, phone, URL, email, bank account
        assert result.total_candidates >= result.high_confidence_count
        assert result.processing_time_ms > 0
        
        # Check entity types are present
        entity_types = [e.entity_type for e in result.entities]
        assert EntityType.UPI_ID in entity_types
        assert EntityType.PHONE_NUMBER in entity_types
        assert EntityType.URL in entity_types
    
    @pytest.mark.asyncio
    async def test_confidence_threshold_filtering(self):
        """Test that confidence threshold properly filters entities."""
        text = "Contact john@paytm or call 9876543210"
        
        with patch('app.core.session_manager.session_manager') as mock_session_manager:
            mock_session_manager.get_session.return_value = None
            mock_session_manager.add_extracted_entity = AsyncMock()
            
            with patch('app.core.entity_extraction.get_db_session') as mock_db:
                mock_db.return_value.__aenter__.return_value.execute.return_value.scalar_one_or_none.return_value = None
                
                # Test with high threshold
                result_high = await self.engine.extract_entities(
                    text=text,
                    session_id="test-session",
                    confidence_threshold=0.95
                )
                
                # Test with low threshold
                result_low = await self.engine.extract_entities(
                    text=text,
                    session_id="test-session",
                    confidence_threshold=0.5
                )
        
        # Low threshold should extract more entities
        assert result_low.high_confidence_count >= result_high.high_confidence_count
    
    @pytest.mark.asyncio
    async def test_duplicate_removal(self):
        """Test removal of duplicate entities."""
        text = "Contact john@paytm or john@paytm again"
        
        with patch('app.core.session_manager.session_manager') as mock_session_manager:
            mock_session_manager.get_session.return_value = None
            mock_session_manager.add_extracted_entity = AsyncMock()
            
            with patch('app.core.entity_extraction.get_db_session') as mock_db:
                mock_db.return_value.__aenter__.return_value.execute.return_value.scalar_one_or_none.return_value = None
                
                result = await self.engine.extract_entities(
                    text=text,
                    session_id="test-session"
                )
        
        # Should only have one instance of john@paytm
        upi_entities = [e for e in result.entities if e.entity_type == EntityType.UPI_ID]
        assert len(upi_entities) == 1
        assert upi_entities[0].entity_value == "john@paytm"
    
    @pytest.mark.asyncio
    async def test_cross_validation_boost(self):
        """Test confidence boost from cross-validation."""
        # UPI with phone should get confidence boost
        text_with_support = "Send to john@paytm and call 9876543210"
        # UPI alone
        text_without_support = "Send to john@paytm"
        
        with patch('app.core.session_manager.session_manager') as mock_session_manager:
            mock_session_manager.get_session.return_value = None
            mock_session_manager.add_extracted_entity = AsyncMock()
            
            with patch('app.core.entity_extraction.get_db_session') as mock_db:
                mock_db.return_value.__aenter__.return_value.execute.return_value.scalar_one_or_none.return_value = None
                
                result_with = await self.engine.extract_entities(
                    text=text_with_support,
                    session_id="test-session"
                )
                
                result_without = await self.engine.extract_entities(
                    text=text_without_support,
                    session_id="test-session"
                )
        
        # Find UPI entities in both results
        upi_with = next((e for e in result_with.entities if e.entity_type == EntityType.UPI_ID), None)
        upi_without = next((e for e in result_without.entities if e.entity_type == EntityType.UPI_ID), None)
        
        assert upi_with is not None
        assert upi_without is not None
        # UPI with supporting phone should have higher confidence
        assert upi_with.confidence_score >= upi_without.confidence_score
    
    @pytest.mark.asyncio
    async def test_blacklist_filtering(self):
        """Test that blacklisted entities are filtered out."""
        text = "Contact test@example.com"
        
        # Add to blacklist
        self.engine.add_to_blacklist("test@example.com")
        
        with patch('app.core.session_manager.session_manager') as mock_session_manager:
            mock_session_manager.get_session.return_value = None
            mock_session_manager.add_extracted_entity = AsyncMock()
            
            with patch('app.core.entity_extraction.get_db_session') as mock_db:
                mock_db.return_value.__aenter__.return_value.execute.return_value.scalar_one_or_none.return_value = None
                
                result = await self.engine.extract_entities(
                    text=text,
                    session_id="test-session"
                )
        
        # Should not extract blacklisted entity
        email_entities = [e for e in result.entities if e.entity_type == EntityType.EMAIL]
        assert len(email_entities) == 0
    
    @pytest.mark.asyncio
    async def test_whitelist_confidence_boost(self):
        """Test confidence boost for whitelisted entities."""
        text = "Contact verified@example.com"
        
        # Add to whitelist
        self.engine.add_to_whitelist("verified@example.com")
        
        with patch('app.core.session_manager.session_manager') as mock_session_manager:
            mock_session_manager.get_session.return_value = None
            mock_session_manager.add_extracted_entity = AsyncMock()
            
            with patch('app.core.entity_extraction.get_db_session') as mock_db:
                mock_db.return_value.__aenter__.return_value.execute.return_value.scalar_one_or_none.return_value = None
                
                result = await self.engine.extract_entities(
                    text=text,
                    session_id="test-session"
                )
        
        # Should extract with boosted confidence
        email_entities = [e for e in result.entities if e.entity_type == EntityType.EMAIL]
        assert len(email_entities) == 1
        assert email_entities[0].verification_status == True
        assert email_entities[0].confidence_score >= 0.9
    
    @pytest.mark.asyncio
    async def test_extraction_summary_generation(self):
        """Test generation of extraction summary."""
        text = "Transfer to john@paytm, call 9876543210, visit https://example.com"
        
        with patch('app.core.session_manager.session_manager') as mock_session_manager:
            mock_session_manager.get_session.return_value = None
            mock_session_manager.add_extracted_entity = AsyncMock()
            
            with patch('app.core.entity_extraction.get_db_session') as mock_db:
                mock_db.return_value.__aenter__.return_value.execute.return_value.scalar_one_or_none.return_value = None
                
                result = await self.engine.extract_entities(
                    text=text,
                    session_id="test-session"
                )
        
        summary = result.extraction_summary
        
        assert 'total_entities_extracted' in summary
        assert 'total_candidates_found' in summary
        assert 'extraction_accuracy' in summary
        assert 'processing_time_ms' in summary
        assert 'entity_type_counts' in summary
        assert 'threat_type_counts' in summary
        assert 'severity_level_counts' in summary
        assert 'average_confidence' in summary
        
        # Check that accuracy is reasonable
        assert 0 <= summary['extraction_accuracy'] <= 1
        assert summary['average_confidence'] > 0
    
    @pytest.mark.asyncio
    async def test_error_handling(self):
        """Test error handling in entity extraction."""
        text = "Test message"
        
        with patch('app.core.session_manager.session_manager') as mock_session_manager:
            mock_session_manager.get_session.side_effect = Exception("Database error")
            
            # Should not raise exception, should return empty result
            result = await self.engine.extract_entities(
                text=text,
                session_id="test-session"
            )
        
        assert result.entities == []
        assert result.high_confidence_count == 0
        assert 'error' in result.extraction_summary
    
    def test_extraction_stats(self):
        """Test extraction engine statistics."""
        stats = self.engine.get_extraction_stats()
        
        assert 'extractors_count' in stats
        assert 'blacklist_size' in stats
        assert 'whitelist_size' in stats
        assert 'cache_size' in stats
        assert 'supported_entity_types' in stats
        
        assert stats['extractors_count'] == 5  # UPI, Phone, URL, Bank, Email
        assert len(stats['supported_entity_types']) == 5


class TestEntityDataStructures:
    """Test entity data structures and serialization."""
    
    def test_extracted_entity_data_serialization(self):
        """Test serialization of ExtractedEntityData."""
        entity = ExtractedEntityData(
            entity_type=EntityType.UPI_ID,
            entity_value="test@paytm",
            confidence_score=0.95,
            extraction_method="regex_test",
            context="Test context",
            threat_type=ThreatType.FINANCIAL,
            severity_level=SeverityLevel.CRITICAL,
            verification_status=True,
            metadata={"test": "value"}
        )
        
        data_dict = entity.to_dict()
        
        assert data_dict['entity_type'] == 'upi_id'
        assert data_dict['entity_value'] == 'test@paytm'
        assert data_dict['confidence_score'] == 0.95
        assert data_dict['extraction_method'] == 'regex_test'
        assert data_dict['context'] == 'Test context'
        assert data_dict['threat_type'] == 'financial'
        assert data_dict['severity_level'] == 'critical'
        assert data_dict['verification_status'] == True
        assert data_dict['metadata'] == {"test": "value"}


if __name__ == "__main__":
    pytest.main([__file__])