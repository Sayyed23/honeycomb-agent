#!/usr/bin/env python3
"""
Local API test script to verify the honeypot API works before deployment.
"""

import asyncio
import aiohttp
import json
import sys
from datetime import datetime

# Test configuration
BASE_URL = "http://localhost:8000"
API_KEY = "iR3PgIodG2xKOCsKa7eNK6HrVKMNHOpzQmfDD6wPs"

async def test_health_endpoint():
    """Test the health endpoint."""
    print("🔍 Testing health endpoint...")
    
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(f"{BASE_URL}/health") as response:
                if response.status == 200:
                    data = await response.json()
                    print(f"✅ Health check passed: {data['status']}")
                    print(f"   Version: {data['version']}")
                    print(f"   Uptime: {data['metrics']['uptime']} seconds")
                    return True
                else:
                    print(f"❌ Health check failed: {response.status}")
                    return False
        except Exception as e:
            print(f"❌ Health check error: {e}")
            return False

async def test_root_endpoint():
    """Test the root endpoint."""
    print("\n🔍 Testing root endpoint...")
    
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(f"{BASE_URL}/") as response:
                if response.status == 200:
                    data = await response.json()
                    print(f"✅ Root endpoint works: {data['app']}")
                    return True
                else:
                    print(f"❌ Root endpoint failed: {response.status}")
                    return False
        except Exception as e:
            print(f"❌ Root endpoint error: {e}")
            return False

async def test_honeypot_endpoint():
    """Test the honeypot endpoint."""
    print("\n🔍 Testing honeypot endpoint...")
    
    headers = {
        "Content-Type": "application/json",
        "x-api-key": API_KEY
    }
    
    payload = {
        "sessionId": "test-session-123",
        "message": "Hello, I am calling from your bank. There is a problem with your account.",
        "conversationHistory": []
    }
    
    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(
                f"{BASE_URL}/api/honeypot", 
                headers=headers, 
                json=payload
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    print(f"✅ Honeypot endpoint works!")
                    print(f"   Status: {data.get('status', 'unknown')}")
                    print(f"   Risk Score: {data.get('riskScore', 'N/A')}")
                    print(f"   Response: {data.get('response', 'N/A')[:100]}...")
                    return True
                else:
                    text = await response.text()
                    print(f"❌ Honeypot endpoint failed: {response.status}")
                    print(f"   Response: {text}")
                    return False
        except Exception as e:
            print(f"❌ Honeypot endpoint error: {e}")
            return False

async def test_honeypot_without_auth():
    """Test the honeypot endpoint without authentication."""
    print("\n🔍 Testing honeypot endpoint without auth...")
    
    headers = {
        "Content-Type": "application/json"
        # No API key
    }
    
    payload = {
        "sessionId": "test-session-123",
        "message": "Hello, I am calling from your bank.",
        "conversationHistory": []
    }
    
    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(
                f"{BASE_URL}/api/honeypot", 
                headers=headers, 
                json=payload
            ) as response:
                if response.status == 401:
                    print("✅ Authentication properly required (401 Unauthorized)")
                    return True
                else:
                    print(f"❌ Expected 401, got {response.status}")
                    return False
        except Exception as e:
            print(f"❌ Auth test error: {e}")
            return False

async def main():
    """Run all tests."""
    print("🚀 Starting local API tests...")
    print(f"   Base URL: {BASE_URL}")
    print(f"   API Key: {API_KEY[:10]}...")
    print(f"   Time: {datetime.now().isoformat()}")
    print("=" * 50)
    
    tests = [
        test_health_endpoint,
        test_root_endpoint,
        test_honeypot_without_auth,
        test_honeypot_endpoint,
    ]
    
    results = []
    for test in tests:
        result = await test()
        results.append(result)
    
    print("\n" + "=" * 50)
    print("📊 Test Results:")
    passed = sum(results)
    total = len(results)
    print(f"   Passed: {passed}/{total}")
    
    if passed == total:
        print("🎉 All tests passed! API is ready for deployment.")
        return 0
    else:
        print("❌ Some tests failed. Check the API before deploying.")
        return 1

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))