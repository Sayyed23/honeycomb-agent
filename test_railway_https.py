#!/usr/bin/env python3
"""
Test Railway deployment with HTTPS instead of HTTP.
"""

import requests
import json

# Configuration - try HTTPS
BASE_URL = "https://1-production-fc5b.up.railway.app"
API_KEY = "iR3PgIodG2xKOCsKa7eNK6HrVKMNHOpzQmfDD6wPs"

def test_https():
    """Test with HTTPS."""
    print(f"🔍 TESTING RAILWAY WITH HTTPS")
    print(f"Target: {BASE_URL}")
    print("=" * 50)
    
    # Test health first
    print("1. Testing Health with HTTPS...")
    try:
        response = requests.get(f"{BASE_URL}/health", timeout=10)
        print(f"   HTTPS Health Status: {response.status_code}")
        if response.status_code == 200:
            print("   ✅ HTTPS Health works!")
        else:
            print(f"   ❌ HTTPS Health failed: {response.text}")
    except Exception as e:
        print(f"   ❌ HTTPS Health Error: {e}")
    
    print()
    
    # Test honeypot with HTTPS
    print("2. Testing Honeypot with HTTPS...")
    headers = {
        "Content-Type": "application/json",
        "x-api-key": API_KEY
    }
    
    data = {
        "sessionId": "https-test",
        "message": "Test message for HTTPS",
        "conversationHistory": []
    }
    
    try:
        response = requests.post(
            f"{BASE_URL}/api/honeypot",
            headers=headers,
            json=data,
            timeout=15
        )
        print(f"   HTTPS POST Status: {response.status_code}")
        print(f"   HTTPS Response: {response.text}")
        
        if response.status_code == 200:
            print("   ✅ HTTPS Honeypot works!")
            return True
        else:
            print(f"   ❌ HTTPS Honeypot failed")
            return False
            
    except Exception as e:
        print(f"   ❌ HTTPS POST Error: {e}")
        return False

if __name__ == "__main__":
    success = test_https()
    
    print("\n" + "=" * 50)
    if success:
        print("🎉 HTTPS WORKS! Use HTTPS URL for evaluation tests.")
    else:
        print("❌ HTTPS also fails. Railway deployment needs investigation.")
    print("=" * 50)