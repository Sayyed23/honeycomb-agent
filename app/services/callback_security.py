"""
Security and data protection for GUVI callback system.
Ensures secure transmission and prevents data exposure.
"""

import hashlib
import hmac
import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os

from config.settings import settings

logger = logging.getLogger(__name__)


class CallbackSecurityManager:
    """Manages security and data protection for GUVI callbacks."""
    
    def __init__(self):
        self._encryption_key = None
        self._initialize_encryption()
    
    def _initialize_encryption(self):
        """Initialize encryption key for sensitive data."""
        # Use API key secret as base for encryption key derivation
        password = settings.api_key_secret.encode()
        salt = b'guvi_callback_salt_2024'  # Fixed salt for consistency
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        self._encryption_key = Fernet(key)
    
    def sanitize_payload_for_transmission(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize payload to ensure no sensitive detection details are exposed.
        
        Args:
            payload: Original GUVI callback payload
            
        Returns:
            Dict: Sanitized payload safe for transmission
        """
        sanitized = payload.copy()
        
        # Remove or sanitize sensitive detection information
        if 'detectionResult' in sanitized:
            detection_result = sanitized['detectionResult'].copy()
            
            # Keep only essential detection information
            sanitized_detection = {
                'isScam': detection_result.get('isScam', False),
                'riskScore': detection_result.get('riskScore', 0.0),
                'confidence': detection_result.get('confidence', 0.0),
                # Remove detailed detection methods and risk factors
                'detectionSummary': 'Automated scam detection analysis completed'
            }
            
            sanitized['detectionResult'] = sanitized_detection
        
        # Sanitize conversation summary to remove sensitive details
        if 'conversationSummary' in sanitized:
            sanitized['conversationSummary'] = self._sanitize_conversation_summary(
                sanitized['conversationSummary']
            )
        
        # Encrypt sensitive extracted entities
        if 'extractedEntities' in sanitized:
            sanitized['extractedEntities'] = self._sanitize_extracted_entities(
                sanitized['extractedEntities']
            )
        
        # Remove detailed system metrics that could reveal internal architecture
        if 'systemMetrics' in sanitized:
            system_metrics = sanitized['systemMetrics'].copy()
            sanitized_metrics = {
                'sessionDuration': system_metrics.get('sessionDuration', 0),
                'totalTurns': system_metrics.get('totalTurns', 0),
                'processingTimestamp': system_metrics.get('processingTimestamp'),
                'systemVersion': system_metrics.get('systemVersion')
            }
            sanitized['systemMetrics'] = sanitized_metrics
        
        # Add security metadata
        sanitized['security'] = {
            'sanitized': True,
            'sanitizedAt': datetime.utcnow().isoformat() + 'Z',
            'version': '1.0'
        }
        
        logger.info(f"Sanitized callback payload for session {payload.get('sessionId')}")
        return sanitized
    
    def _sanitize_conversation_summary(self, summary: str) -> str:
        """Sanitize conversation summary to remove sensitive information."""
        # Remove specific message content, keep only metadata
        parts = summary.split(' | ')
        sanitized_parts = []
        
        for part in parts:
            if part.startswith('Initial Message:') or part.startswith('Final Message:'):
                # Replace actual message content with generic description
                if 'Initial Message:' in part:
                    sanitized_parts.append('Initial Message: [Content sanitized for security]')
                elif 'Final Message:' in part:
                    sanitized_parts.append('Final Message: [Content sanitized for security]')
            else:
                # Keep metadata like duration, turns, etc.
                sanitized_parts.append(part)
        
        return ' | '.join(sanitized_parts)
    
    def _sanitize_extracted_entities(self, entities: list) -> list:
        """Sanitize extracted entities to protect sensitive information."""
        sanitized_entities = []
        
        for entity in entities:
            sanitized_entity = {
                'type': entity.get('type'),
                'confidence': entity.get('confidence'),
                'extractionMethod': entity.get('extractionMethod'),
                'verified': entity.get('verified', False),
                'extractedAt': entity.get('extractedAt')
            }
            
            # Hash sensitive values instead of sending them directly
            if 'value' in entity:
                sanitized_entity['valueHash'] = self._hash_sensitive_value(entity['value'])
                # Only include partial value for verification purposes
                sanitized_entity['partialValue'] = self._create_partial_value(
                    entity['value'], entity.get('type')
                )
            
            # Sanitize context to remove surrounding message content
            if 'context' in entity and entity['context']:
                sanitized_entity['contextLength'] = len(entity['context'])
                sanitized_entity['contextSanitized'] = True
            
            sanitized_entities.append(sanitized_entity)
        
        return sanitized_entities
    
    def _hash_sensitive_value(self, value: str) -> str:
        """Create a secure hash of sensitive values for verification."""
        # Use HMAC with secret key for secure hashing
        secret_key = settings.api_key_secret.encode()
        return hmac.new(
            secret_key,
            value.encode(),
            hashlib.sha256
        ).hexdigest()
    
    def _create_partial_value(self, value: str, entity_type: str) -> str:
        """Create a partial value for verification while protecting sensitive data."""
        if not value:
            return ""
        
        if entity_type == 'phone_number':
            # Show only country code and last 2 digits
            if len(value) > 4:
                return f"{value[:2]}****{value[-2:]}"
            return "****"
        
        elif entity_type == 'upi_id':
            # Show only the domain part
            if '@' in value:
                parts = value.split('@')
                return f"****@{parts[-1]}"
            return "****"
        
        elif entity_type == 'email':
            # Show only domain
            if '@' in value:
                parts = value.split('@')
                return f"****@{parts[-1]}"
            return "****"
        
        elif entity_type == 'url':
            # Show only domain
            try:
                from urllib.parse import urlparse
                parsed = urlparse(value)
                return f"{parsed.scheme}://{parsed.netloc}/****"
            except:
                return "****"
        
        elif entity_type == 'bank_account':
            # Show only last 4 digits
            if len(value) > 4:
                return f"****{value[-4:]}"
            return "****"
        
        else:
            # Generic partial value
            if len(value) > 6:
                return f"{value[:2]}****{value[-2:]}"
            return "****"
    
    def generate_callback_signature(self, payload: Dict[str, Any]) -> str:
        """
        Generate HMAC signature for callback payload authentication.
        
        Args:
            payload: Callback payload
            
        Returns:
            str: HMAC signature
        """
        # Create canonical string representation of payload
        canonical_payload = json.dumps(payload, sort_keys=True, separators=(',', ':'))
        
        # Generate HMAC signature
        secret_key = settings.guvi.api_key.encode()
        signature = hmac.new(
            secret_key,
            canonical_payload.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return signature
    
    def verify_callback_integrity(self, payload: Dict[str, Any], signature: str) -> bool:
        """
        Verify callback payload integrity using HMAC signature.
        
        Args:
            payload: Callback payload
            signature: Expected signature
            
        Returns:
            bool: True if signature is valid
        """
        expected_signature = self.generate_callback_signature(payload)
        return hmac.compare_digest(expected_signature, signature)
    
    def encrypt_sensitive_data(self, data: str) -> str:
        """
        Encrypt sensitive data for storage or transmission.
        
        Args:
            data: Sensitive data to encrypt
            
        Returns:
            str: Encrypted data (base64 encoded)
        """
        encrypted = self._encryption_key.encrypt(data.encode())
        return base64.b64encode(encrypted).decode()
    
    def decrypt_sensitive_data(self, encrypted_data: str) -> str:
        """
        Decrypt sensitive data.
        
        Args:
            encrypted_data: Base64 encoded encrypted data
            
        Returns:
            str: Decrypted data
        """
        encrypted_bytes = base64.b64decode(encrypted_data.encode())
        decrypted = self._encryption_key.decrypt(encrypted_bytes)
        return decrypted.decode()
    
    def validate_callback_authorization(self, api_key: str) -> bool:
        """
        Validate that the callback is authorized to access GUVI endpoints.
        
        Args:
            api_key: API key for authorization
            
        Returns:
            bool: True if authorized
        """
        # Verify API key matches expected GUVI API key
        return hmac.compare_digest(api_key, settings.guvi.api_key)
    
    def audit_callback_security(self, session_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Audit callback for security compliance.
        
        Args:
            session_id: Session identifier
            payload: Callback payload
            
        Returns:
            Dict: Security audit results
        """
        audit_results = {
            'session_id': session_id,
            'audit_timestamp': datetime.utcnow().isoformat() + 'Z',
            'security_checks': {}
        }
        
        # Check if payload is sanitized
        audit_results['security_checks']['payload_sanitized'] = (
            payload.get('security', {}).get('sanitized', False)
        )
        
        # Check for sensitive data exposure
        sensitive_data_exposed = False
        
        # Check detection result for sensitive information
        detection_result = payload.get('detectionResult', {})
        if 'detectionMethods' in detection_result or 'riskFactors' in detection_result:
            sensitive_data_exposed = True
        
        # Check conversation summary for message content
        conversation_summary = payload.get('conversationSummary', '')
        if 'Initial Message:' in conversation_summary and '[Content sanitized' not in conversation_summary:
            sensitive_data_exposed = True
        
        # Check entities for raw values
        entities = payload.get('extractedEntities', [])
        for entity in entities:
            if 'value' in entity and 'valueHash' not in entity:
                sensitive_data_exposed = True
                break
        
        audit_results['security_checks']['sensitive_data_exposed'] = sensitive_data_exposed
        
        # Check for required security metadata
        audit_results['security_checks']['security_metadata_present'] = (
            'security' in payload
        )
        
        # Overall security compliance
        audit_results['security_compliant'] = (
            audit_results['security_checks']['payload_sanitized'] and
            not audit_results['security_checks']['sensitive_data_exposed'] and
            audit_results['security_checks']['security_metadata_present']
        )
        
        if not audit_results['security_compliant']:
            logger.warning(f"Security audit failed for callback {session_id}: {audit_results}")
        else:
            logger.info(f"Security audit passed for callback {session_id}")
        
        return audit_results


# Global security manager instance
callback_security = CallbackSecurityManager()