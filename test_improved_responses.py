#!/usr/bin/env python3
"""
Test the improved honeypot responses.
"""

import requests
import json

# Configuration
BASE_URL = "http://localhost:8000"  # Test locally first
API_KEY = "iR3PgIodG2xKOCsKa7eNK6HrVKMNHOpzQmfDD6wPs"

def test_improved_responses():
    """Test the improved honeypot responses."""
    print("🧪 Testing Improved Honeypot Responses")
    print("=" * 50)
    
    headers = {
        "Content-Type": "application/json",
        "x-api-key": API_KEY
    }
    
    test_cases = [
        {
            "name": "Bank Account Scam",
            "message": "URGENT: Your SBI account has been compromised. Your account will be blocked in 2 hours. Share your account number and OTP immediately to verify your identity.",
            "expected_improvement": "Should show concern and ask for help, not dismiss"
        },
        {
            "name": "Prize/Lottery Scam", 
            "message": "Congratulations! You have won Rs 50,000 in our lottery. To claim your prize, please provide your bank details and pay processing fee of Rs 500.",
            "expected_improvement": "Should show excitement and ask how to claim"
        },
        {
            "name": "Tech Support Scam",
            "message": "Your computer has been infected with virus. Download our software immediately to clean your system. Click this link now.",
            "expected_improvement": "Should ask for help and show concern about computer"
        },
        {
            "name": "Generic Scam",
            "message": "Hello, I have important information for you. Please contact me urgently for financial opportunity.",
            "expected_improvement": "Should ask for more details and show interest"
        }
    ]
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n📝 Test Case {i}: {test_case['name']}")
        print(f"Message: {test_case['message'][:60]}...")
        print(f"Expected: {test_case['expected_improvement']}")
        
        data = {
            "sessionId": f"improved-test-{i}",
            "message": test_case['message'],
            "conversationHistory": []
        }
        
        try:
            response = requests.post(
                f"{BASE_URL}/api/honeypot",
                headers=headers,
                json=data,
                timeout=15
            )
            
            if response.status_code == 200:
                result = response.json()
                reply = result.get('reply', 'No reply')
                print(f"✅ Response: {reply}")
                
                # Check if response is engaging
                engaging_indicators = [
                    'what', 'how', 'help', 'worried', 'concerned', 'explain', 
                    'understand', 'details', 'information', 'really', 'oh no',
                    'scary', 'serious', 'urgent', 'fix', 'problem'
                ]
                
                reply_lower = reply.lower()
                engagement_score = sum(1 for indicator in engaging_indicators if indicator in reply_lower)
                
                if engagement_score >= 2:
                    print(f"🎯 Engagement Score: {engagement_score}/10 - Good!")
                elif engagement_score >= 1:
                    print(f"⚠️ Engagement Score: {engagement_score}/10 - Moderate")
                else:
                    print(f"❌ Engagement Score: {engagement_score}/10 - Poor")
                    
            else:
                print(f"❌ Failed: HTTP {response.status_code}")
                print(f"Response: {response.text}")
                
        except Exception as e:
            print(f"❌ Error: {e}")
    
    print("\n" + "=" * 50)
    print("🎯 Test completed! Check if responses are more engaging than before.")

if __name__ == "__main__":
    test_improved_responses()