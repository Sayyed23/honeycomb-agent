#!/usr/bin/env python3
"""
Simple test for Railway deployment with proper POST request.
"""

import requests
import json

# Configuration
BASE_URL = "http://1-production-fc5b.up.railway.app"
API_KEY = "iR3PgIodG2xKOCsKa7eNK6HrVKMNHOpzQmfDD6wPs"

def test_railway_honeypot():
    """Test Railway honeypot endpoint with proper POST request."""
    print(f"🚀 Testing Railway Deployment: {BASE_URL}")
    print("=" * 50)
    
    # Test health first
    print("🔍 Testing Health...")
    try:
        health_response = requests.get(f"{BASE_URL}/health", timeout=10)
        print(f"   Health Status: {health_response.status_code}")
        if health_response.status_code == 200:
            health_data = health_response.json()
            print(f"   Status: {health_data.get('status', 'unknown')}")
        print()
    except Exception as e:
        print(f"   Health Error: {e}")
        return
    
    # Test honeypot endpoint
    print("🍯 Testing Honeypot Endpoint...")
    
    headers = {
        "Content-Type": "application/json",
        "x-api-key": API_KEY
    }
    
    data = {
        "sessionId": "railway-test-001",
        "message": "URGENT! Your bank account will be blocked. Send OTP immediately to verify.",
        "conversationHistory": []
    }
    
    try:
        print(f"   Making POST request to: {BASE_URL}/api/honeypot")
        print(f"   Headers: {headers}")
        print(f"   Data: {json.dumps(data, indent=2)}")
        print()
        
        response = requests.post(
            f"{BASE_URL}/api/honeypot",
            headers=headers,
            json=data,
            timeout=30
        )
        
        print(f"   Response Status: {response.status_code}")
        print(f"   Response Headers: {dict(response.headers)}")
        print(f"   Response Text: {response.text}")
        
        if response.status_code == 200:
            try:
                json_data = response.json()
                print(f"\n   ✅ SUCCESS!")
                print(f"   Status: {json_data.get('status', 'N/A')}")
                print(f"   Reply: {json_data.get('reply', 'N/A')}")
                
                # Check required fields
                has_status = 'status' in json_data
                has_reply = 'reply' in json_data
                print(f"   Required Fields: status={has_status}, reply={has_reply}")
                
                if has_status and has_reply:
                    print(f"\n   🎉 Railway deployment is working correctly!")
                    return True
                else:
                    print(f"\n   ❌ Missing required fields in response")
                    return False
                    
            except json.JSONDecodeError as e:
                print(f"\n   ❌ Invalid JSON response: {e}")
                return False
        else:
            print(f"\n   ❌ Request failed with status {response.status_code}")
            return False
            
    except Exception as e:
        print(f"   ❌ Request error: {e}")
        return False

if __name__ == "__main__":
    success = test_railway_honeypot()
    
    print("\n" + "=" * 50)
    if success:
        print("🎯 RAILWAY DEPLOYMENT: READY FOR EVALUATION!")
        print("\nNext steps:")
        print("1. Run comprehensive tests: python test_evaluation_readiness.py")
        print("2. Your API is ready for the evaluation!")
    else:
        print("❌ RAILWAY DEPLOYMENT: NEEDS ATTENTION")
        print("\nTroubleshooting:")
        print("1. Check Railway logs for errors")
        print("2. Verify environment variables are set")
        print("3. Test locally first: python test_local_evaluation.py")
    print("=" * 50)