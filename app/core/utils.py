"""
Core utility functions for the honeypot application.
"""

import hashlib
import json
from typing import Any, Dict, List, Optional
import re
from datetime import datetime


def hash_message(content: str, metadata: Optional[Dict[str, Any]] = None) -> str:
    """
    Generate a consistent hash for message content and metadata.
    
    Args:
        content: Message content
        metadata: Optional metadata dictionary
        
    Returns:
        str: SHA-256 hash of the message
    """
    # Create a consistent representation for hashing
    hash_data = {
        'content': content.strip().lower(),
        'metadata': metadata or {}
    }
    
    # Sort keys for consistent hashing
    hash_string = json.dumps(hash_data, sort_keys=True, ensure_ascii=True, default=str)    
    # Generate SHA-256 hash
    return hashlib.sha256(hash_string.encode('utf-8')).hexdigest()


def sanitize_input(text: str, max_length: int = 5000) -> str:
    """
    Sanitize input text by removing potentially harmful content.
    
    Args:
        text: Input text to sanitize
        max_length: Maximum allowed length
        
    Returns:
        str: Sanitized text
    """
    if not text:
        return ""
    
    # Truncate to max length
    text = text[:max_length]
    
    # Remove null bytes and control characters (except newlines and tabs)
    text = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', text)
    
    # Remove excessive whitespace
    text = re.sub(r'\s+', ' ', text)
    
    return text.strip()


def extract_language_hints(text: str) -> str:
    """
    Extract language hints from text content.
    
    Args:
        text: Input text
        
    Returns:
        str: Detected language code ('en', 'hi', 'hinglish')
    """
    if not text:
        return 'en'
    
    # Simple heuristics for language detection
    hindi_chars = len(re.findall(r'[\u0900-\u097F]', text))
    english_chars = len(re.findall(r'[a-zA-Z]', text))
    total_chars = len(text.replace(' ', ''))
    
    if total_chars == 0:
        return 'en'
    
    hindi_ratio = hindi_chars / total_chars
    english_ratio = english_chars / total_chars
    
    # Language detection logic
    if hindi_ratio > 0.5:
        return 'hi'
    elif hindi_ratio > 0.1 and english_ratio > 0.3:
        return 'hinglish'
    else:
        return 'en'


def format_duration(seconds: int) -> str:
    """
    Format duration in seconds to human-readable string.
    
    Args:
        seconds: Duration in seconds
        
    Returns:
        str: Formatted duration string
    """
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        minutes = seconds // 60
        remaining_seconds = seconds % 60
        return f"{minutes}m {remaining_seconds}s"
    else:
        hours = seconds // 3600
        remaining_minutes = (seconds % 3600) // 60
        return f"{hours}h {remaining_minutes}m"


def validate_session_id(session_id: str) -> bool:
    """
    Validate session ID format.
    
    Args:
        session_id: Session ID to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    if not session_id:
        return False
    
    # Check length (1-100 characters)
    if len(session_id) < 1 or len(session_id) > 100:
        return False
    
    # Check format (alphanumeric with hyphens and underscores)
    if not re.match(r'^[a-zA-Z0-9_-]+$', session_id):
        return False
    
    return True


def truncate_text(text: str, max_length: int = 200, suffix: str = "...") -> str:
    """
    Truncate text to specified length with suffix.
    
    Args:
        text: Text to truncate
        max_length: Maximum length
        suffix: Suffix to add if truncated
        
    Returns:
        str: Truncated text
    """
    if not text or len(text) <= max_length:
        return text
    
    return text[:max_length - len(suffix)] + suffix


def extract_metadata_summary(metadata: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract and summarize important metadata fields.
    
    Args:
        metadata: Full metadata dictionary
        
    Returns:
        Dict[str, Any]: Summarized metadata
    """
    summary = {}
    
    # Extract important fields
    important_fields = [
        'userAgent', 'ipAddress', 'platform', 'language',
        'timestamp', 'source', 'channel'
    ]
    
    for field in important_fields:
        if field in metadata:
            summary[field] = metadata[field]
    
    return summary


def calculate_text_similarity(text1: str, text2: str) -> float:
    """
    Calculate simple text similarity using character overlap.
    
    Args:
        text1: First text
        text2: Second text
        
    Returns:
        float: Similarity score (0.0-1.0)
    """
    if not text1 or not text2:
        return 0.0
    
    # Convert to lowercase and create character sets
    set1 = set(text1.lower())
    set2 = set(text2.lower())
    
    # Calculate Jaccard similarity
    intersection = len(set1.intersection(set2))
    union = len(set1.union(set2))
    
    return intersection / union if union > 0 else 0.0


def is_valid_timestamp(timestamp_str: str) -> bool:
    """
    Validate ISO 8601 timestamp format.
    
    Args:
        timestamp_str: Timestamp string to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    try:
        datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        return True
    except (ValueError, AttributeError):
        return False


def normalize_phone_number(phone: str) -> Optional[str]:
    """
    Normalize phone number format.
    
    Args:
        phone: Phone number string
        
    Returns:
        Optional[str]: Normalized phone number or None if invalid
    """
    if not phone:
        return None
    
    # Remove all non-digit characters
    digits = re.sub(r'\D', '', phone)
    
    # Check if it's a valid length
    if len(digits) < 10 or len(digits) > 15:
        return None
    
    # Add country code if missing (assume India +91)
    if len(digits) == 10:
        digits = '91' + digits
    
    return '+' + digits


def normalize_upi_id(upi: str) -> Optional[str]:
    """
    Normalize UPI ID format.
    
    Args:
        upi: UPI ID string
        
    Returns:
        Optional[str]: Normalized UPI ID or None if invalid
    """
    if not upi:
        return None
    
    # Basic UPI format validation
    upi = upi.strip().lower()
    
    # Check basic format: something@something
    if '@' not in upi or upi.count('@') != 1:
        return None
    
    parts = upi.split('@')
    if len(parts[0]) < 3 or len(parts[1]) < 3:
        return None
    
    return upi