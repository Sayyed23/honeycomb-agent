#!/usr/bin/env python3
"""
Simple script to test the honeypot API locally and remotely.
"""

import requests
import json

# Test data
test_request_simple = {
    "sessionId": "test-session-123",
    "message": "Hello, I am calling from your bank. There is a problem with your account.",
    "conversationHistory": []
}

test_request_full = {
    "sessionId": "test-session-123",
    "message": {
        "sender": "scammer",
        "text": "Hello, I am calling from your bank. There is a problem with your account.",
        "timestamp": "2024-02-04T15:59:00Z"
    },
    "conversationHistory": [],
    "metadata": {
        "channel": "web",
        "language": "en",
        "locale": "en-US"
    }
}

# API configuration
API_KEY = "iR3PgIodG2xKOCsKa7eNK6HrVKMNHOpzQmfDD6wPs"
BASE_URLS = [
    "https://jt-production-fc5b.up.railway.app",
    "http://localhost:8000"  # Fallback for local testing
]

headers = {
    "Content-Type": "application/json",
    "x-api-key": API_KEY
}

def test_health(base_url):
    """Test health endpoint"""
    print(f"Testing health endpoint at {base_url}...")
    try:
        response = requests.get(f"{base_url}/health", timeout=10)
        print(f"Health Status: {response.status_code}")
        print(f"Health Response: {response.text}")
        return response.status_code == 200
    except Exception as e:
        print(f"Health check failed: {e}")
        return False

def test_honeypot_simple(base_url):
    """Test honeypot with simple message"""
    print(f"\nTesting honeypot with simple message at {base_url}...")
    try:
        response = requests.post(
            f"{base_url}/api/honeypot",
            headers=headers,
            json=test_request_simple,
            timeout=10
        )
        print(f"Simple Status: {response.status_code}")
        print(f"Simple Response: {response.text}")
        return response.status_code == 200
    except Exception as e:
        print(f"Simple test failed: {e}")
        return False

def test_honeypot_full(base_url):
    """Test honeypot with full message object"""
    print(f"\nTesting honeypot with full message object at {base_url}...")
    try:
        response = requests.post(
            f"{base_url}/api/honeypot",
            headers=headers,
            json=test_request_full,
            timeout=10
        )
        print(f"Full Status: {response.status_code}")
        print(f"Full Response: {response.text}")
        return response.status_code == 200
    except Exception as e:
        print(f"Full test failed: {e}")
        return False

if __name__ == "__main__":
    print("=== API Testing Script ===")
    
    for base_url in BASE_URLS:
        print(f"\n{'='*50}")
        print(f"Testing: {base_url}")
        print(f"{'='*50}")
        
        # Test health first
        health_ok = test_health(base_url)
        
        if health_ok:
            print("\n✅ Health check passed, testing honeypot endpoints...")
            
            # Test simple format
            simple_ok = test_honeypot_simple(base_url)
            
            # Test full format
            full_ok = test_honeypot_full(base_url)
            
            print(f"\n=== Results for {base_url} ===")
            print(f"Health: {'✅' if health_ok else '❌'}")
            print(f"Simple: {'✅' if simple_ok else '❌'}")
            print(f"Full: {'✅' if full_ok else '❌'}")
            
            if health_ok and simple_ok and full_ok:
                print(f"\n🎉 All tests passed for {base_url}!")
                break
            
        else:
            print(f"\n❌ Health check failed for {base_url}")
    
    print(f"\n{'='*50}")
    print("Testing complete!")