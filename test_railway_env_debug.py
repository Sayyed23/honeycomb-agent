#!/usr/bin/env python3
"""
Debug Railway environment variable issues.
"""

import requests
import json

# Configuration
BASE_URL = "https://1-production-fc5b.up.railway.app"
API_KEY = "iR3PgIodG2xKOCsKa7eNK6HrVKMNHOpzQmfDD6wPs"

def test_env_debug():
    """Test environment variable issues."""
    print(f"🔍 DEBUGGING RAILWAY ENVIRONMENT VARIABLES")
    print(f"Target: {BASE_URL}")
    print("=" * 60)
    
    # Test data
    data = {
        "sessionId": "env-debug-test",
        "message": "Environment debug test",
        "conversationHistory": []
    }
    
    # Test different API key scenarios
    api_key_tests = [
        ("Current API Key", API_KEY),
        ("Empty API Key", ""),
        ("Wrong API Key", "wrong-key"),
        ("Test API Key", "test-api-key"),  # Sometimes used in examples
    ]
    
    for test_name, test_key in api_key_tests:
        print(f"\n{test_name}: {test_key[:20]}...")
        
        headers = {
            "Content-Type": "application/json",
            "x-api-key": test_key
        }
        
        try:
            response = requests.post(
                f"{BASE_URL}/api/honeypot",
                headers=headers,
                json=data,
                timeout=10
            )
            print(f"   Status: {response.status_code}")
            print(f"   Response: {response.text}")
            
            if response.status_code == 200:
                print(f"   ✅ SUCCESS with {test_name}!")
                return test_key
                
        except Exception as e:
            print(f"   Error: {e}")
    
    # Test without API key header
    print(f"\nNo API Key Header:")
    try:
        response = requests.post(
            f"{BASE_URL}/api/honeypot",
            headers={"Content-Type": "application/json"},
            json=data,
            timeout=10
        )
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.text}")
    except Exception as e:
        print(f"   Error: {e}")
    
    # Check what the health endpoint says about environment
    print(f"\nChecking health endpoint for environment info...")
    try:
        response = requests.get(f"{BASE_URL}/health", timeout=10)
        if response.status_code == 200:
            health_data = response.json()
            print(f"   Environment info from health:")
            print(f"   - Status: {health_data.get('status')}")
            print(f"   - Version: {health_data.get('version')}")
            print(f"   - Components: {health_data.get('components', {})}")
    except Exception as e:
        print(f"   Health check error: {e}")
    
    return None

if __name__ == "__main__":
    working_key = test_env_debug()
    
    print("\n" + "=" * 60)
    if working_key:
        print(f"🎉 FOUND WORKING API KEY: {working_key}")
        print("Update your test scripts with this key!")
    else:
        print("❌ NO WORKING API KEY FOUND")
        print("Railway environment variables need to be checked:")
        print("1. Go to Railway dashboard")
        print("2. Check Variables tab")
        print("3. Ensure x_API_KEY is set correctly")
        print("4. Redeploy if needed")
    print("=" * 60)