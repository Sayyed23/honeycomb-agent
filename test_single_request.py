#!/usr/bin/env python3
"""
Test a single request to verify the server is working with new responses.
"""

import requests
import json

# Configuration
BASE_URL = "http://localhost:8000"
API_KEY = "iR3PgIodG2xKOCsKa7eNK6HrVKMNHOpzQmfDD6wPs"

def test_single_request():
    """Test a single request."""
    print("🧪 Testing Single Request")
    print("=" * 30)
    
    headers = {
        "Content-Type": "application/json",
        "x-api-key": API_KEY
    }
    
    data = {
        "sessionId": "test-single",
        "message": "URGENT: Your SBI account has been compromised. Your account will be blocked in 2 hours. Share your account number and OTP immediately to verify your identity.",
        "conversationHistory": []
    }
    
    try:
        print("Making request...")
        response = requests.post(
            f"{BASE_URL}/api/honeypot",
            headers=headers,
            json=data,
            timeout=10
        )
        
        print(f"Status: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            reply = result.get('reply', 'No reply')
            print(f"Response: {reply}")
            
            # Check if it's the old generic response
            if "I'm not sure what you mean" in reply or "I'll get back to you" in reply or "Let me think about it" in reply:
                print("❌ Still using old generic responses!")
                return False
            else:
                print("✅ Using new realistic responses!")
                return True
        else:
            print(f"❌ Error: {response.status_code}")
            print(f"Response: {response.text}")
            return False
            
    except requests.exceptions.ConnectionError:
        print("❌ Connection failed - server not running")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

if __name__ == "__main__":
    success = test_single_request()
    if success:
        print("\n🎉 Server is working with new responses!")
    else:
        print("\n❌ Server needs to be restarted with new code.")
        print("Run: python -m uvicorn app.main:app --host 0.0.0.0 --port 8000")