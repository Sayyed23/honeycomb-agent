#!/usr/bin/env python3
"""
Debug Railway deployment issues with detailed logging.
"""

import requests
import json

# Configuration
BASE_URL = "http://1-production-fc5b.up.railway.app"
API_KEY = "iR3PgIodG2xKOCsKa7eNK6HrVKMNHOpzQmfDD6wPs"

def test_with_debug():
    """Test with detailed debugging."""
    print(f"🔍 DEBUGGING RAILWAY DEPLOYMENT")
    print(f"Target: {BASE_URL}")
    print("=" * 60)
    
    # Test 1: Check if the endpoint exists with OPTIONS
    print("1. Testing OPTIONS request (CORS preflight)...")
    try:
        response = requests.options(f"{BASE_URL}/api/honeypot", timeout=10)
        print(f"   OPTIONS Status: {response.status_code}")
        print(f"   Allow Header: {response.headers.get('Allow', 'Not present')}")
        print(f"   CORS Headers: {response.headers.get('Access-Control-Allow-Methods', 'Not present')}")
    except Exception as e:
        print(f"   OPTIONS Error: {e}")
    
    print()
    
    # Test 2: Try POST with minimal data
    print("2. Testing POST with minimal data...")
    headers = {
        "Content-Type": "application/json",
        "x-api-key": API_KEY
    }
    
    minimal_data = {
        "sessionId": "debug-test",
        "message": "test",
        "conversationHistory": []
    }
    
    try:
        response = requests.post(
            f"{BASE_URL}/api/honeypot",
            headers=headers,
            json=minimal_data,
            timeout=10
        )
        print(f"   POST Status: {response.status_code}")
        print(f"   Response Headers: {dict(response.headers)}")
        print(f"   Response Body: {response.text}")
    except Exception as e:
        print(f"   POST Error: {e}")
    
    print()
    
    # Test 3: Try different header variations
    print("3. Testing different API key header variations...")
    
    header_variations = [
        {"Content-Type": "application/json", "x-api-key": API_KEY},
        {"Content-Type": "application/json", "X-API-KEY": API_KEY},
        {"Content-Type": "application/json", "X-Api-Key": API_KEY},
    ]
    
    for i, headers in enumerate(header_variations, 1):
        print(f"   Variation {i}: {headers}")
        try:
            response = requests.post(
                f"{BASE_URL}/api/honeypot",
                headers=headers,
                json=minimal_data,
                timeout=10
            )
            print(f"     Status: {response.status_code}")
            if response.status_code != 405:
                print(f"     Body: {response.text}")
        except Exception as e:
            print(f"     Error: {e}")
    
    print()
    
    # Test 4: Compare with local
    print("4. Comparing with local deployment...")
    try:
        local_response = requests.post(
            "http://localhost:8000/api/honeypot",
            headers={"Content-Type": "application/json", "x-api-key": API_KEY},
            json=minimal_data,
            timeout=10
        )
        print(f"   Local Status: {local_response.status_code}")
        print(f"   Local Response: {local_response.text[:100]}...")
    except Exception as e:
        print(f"   Local Error: {e}")
    
    print()
    
    # Test 5: Check Railway-specific headers
    print("5. Testing with Railway-specific considerations...")
    railway_headers = {
        "Content-Type": "application/json",
        "x-api-key": API_KEY,
        "User-Agent": "Railway-Test/1.0",
        "Accept": "application/json"
    }
    
    try:
        response = requests.post(
            f"{BASE_URL}/api/honeypot",
            headers=railway_headers,
            json=minimal_data,
            timeout=10
        )
        print(f"   Railway-specific Status: {response.status_code}")
        print(f"   Railway-specific Response: {response.text}")
    except Exception as e:
        print(f"   Railway-specific Error: {e}")

if __name__ == "__main__":
    test_with_debug()