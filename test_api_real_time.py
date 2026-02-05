#!/usr/bin/env python3
"""
Real-time API tester for the Honeypot API.
Tests both health and honeypot endpoints.
"""

import requests
import json
import time

# API Configuration
BASE_URL = "http://localhost:8000"
API_KEY = "iR3PgIodG2xKOCsKa7eNK6HrVKMNHOpzQmfDD6wPs"

def test_health_endpoint():
    """Test the health endpoint."""
    print("🔍 Testing Health Endpoint...")
    
    try:
        response = requests.get(f"{BASE_URL}/health", timeout=10)
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.json()}")
        
        if response.status_code == 200:
            print("✅ Health endpoint is working!")
            return True
        else:
            print("❌ Health endpoint failed!")
            return False
            
    except Exception as e:
        print(f"❌ Health endpoint error: {e}")
        return False

def test_honeypot_endpoint():
    """Test the honeypot endpoint."""
    print("\n🍯 Testing Honeypot Endpoint...")
    
    headers = {
        "Content-Type": "application/json",
        "x-api-key": API_KEY
    }
    
    test_cases = [
        {
            "name": "Simple Scam Message",
            "data": {
                "sessionId": "test-session-001",
                "message": "URGENT! Your bank account will be blocked. Send OTP immediately to verify.",
                "conversationHistory": []
            }
        },
        {
            "name": "Legitimate Message",
            "data": {
                "sessionId": "test-session-002", 
                "message": "Hello, how are you doing today? Hope you are well.",
                "conversationHistory": []
            }
        },
        {
            "name": "Complex Scam with History",
            "data": {
                "sessionId": "test-session-003",
                "message": "I am bank manager. Your account has suspicious activity. Give me your PIN.",
                "conversationHistory": [
                    {
                        "sender": "scammer",
                        "text": "Hello sir, I am calling from your bank",
                        "timestamp": "2026-02-04T16:00:00Z"
                    }
                ]
            }
        }
    ]
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n📝 Test Case {i}: {test_case['name']}")
        
        try:
            response = requests.post(
                f"{BASE_URL}/api/honeypot",
                headers=headers,
                json=test_case['data'],
                timeout=30
            )
            
            print(f"Status Code: {response.status_code}")
            
            if response.status_code == 200:
                result = response.json()
                print(f"✅ Success!")
                print(f"Reply: {result.get('reply', 'No reply')}")
                print(f"Status: {result.get('status', 'No status')}")
            else:
                print(f"❌ Failed!")
                print(f"Response: {response.text}")
                
        except Exception as e:
            print(f"❌ Error: {e}")
        
        # Small delay between requests
        time.sleep(1)

def main():
    """Main test function."""
    print("🚀 Starting Real-Time API Tests")
    print("=" * 50)
    
    # Test health first
    health_ok = test_health_endpoint()
    
    if health_ok:
        # Test honeypot endpoint
        test_honeypot_endpoint()
    else:
        print("\n❌ Skipping honeypot tests due to health check failure")
    
    print("\n" + "=" * 50)
    print("🏁 Tests completed!")

if __name__ == "__main__":
    main()