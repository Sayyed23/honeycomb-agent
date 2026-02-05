#!/usr/bin/env python3
"""
Discovery script to find the correct Railway deployment URL and available endpoints.
"""

import requests
import json

# Possible URLs to try
POSSIBLE_URLS = [
    "https://1-production-fc5b.up.railway.app",
    "http://1-production-fc5b.up.railway.app",
]

# Endpoints to test
ENDPOINTS_TO_TEST = [
    "/",
    "/health",
    "/ready", 
    "/docs",
    "/api/honeypot"
]

API_KEY = "iR3PgIodG2xKOCsKa7eNK6HrVKMNHOpzQmfDD6wPs"

def test_url_and_endpoints(base_url):
    """Test a base URL with various endpoints."""
    print(f"\n🔍 Testing: {base_url}")
    print("-" * 50)
    
    working_endpoints = []
    
    for endpoint in ENDPOINTS_TO_TEST:
        full_url = base_url + endpoint
        try:
            # For API endpoints, include API key
            headers = {}
            if endpoint == "/api/honeypot":
                headers = {
                    "Content-Type": "application/json",
                    "x-api-key": API_KEY
                }
                # Use POST for honeypot endpoint
                response = requests.post(
                    full_url, 
                    headers=headers,
                    json={
                        "sessionId": "discovery-test",
                        "message": "test message",
                        "conversationHistory": []
                    },
                    timeout=10
                )
            else:
                # Use GET for other endpoints
                response = requests.get(full_url, timeout=10)
            
            status_icon = "✅" if response.status_code < 400 else "⚠️" if response.status_code < 500 else "❌"
            print(f"   {status_icon} {endpoint}: HTTP {response.status_code}")
            
            if response.status_code < 400:
                working_endpoints.append(endpoint)
                
                # Show response preview for successful requests
                try:
                    if response.headers.get('content-type', '').startswith('application/json'):
                        json_data = response.json()
                        preview = json.dumps(json_data, indent=2)[:200]
                        print(f"      Response: {preview}...")
                    else:
                        preview = response.text[:100]
                        print(f"      Response: {preview}...")
                except:
                    print(f"      Response: {response.text[:100]}...")
            
        except requests.exceptions.ConnectionError:
            print(f"   ❌ {endpoint}: Connection failed")
        except requests.exceptions.Timeout:
            print(f"   ⏱️ {endpoint}: Timeout")
        except Exception as e:
            print(f"   ❌ {endpoint}: {str(e)[:50]}...")
    
    return working_endpoints

def main():
    """Main discovery function."""
    print("🔍 RAILWAY DEPLOYMENT DISCOVERY")
    print("=" * 60)
    print("Searching for active Railway deployment and available endpoints...")
    
    all_results = {}
    
    for url in POSSIBLE_URLS:
        working_endpoints = test_url_and_endpoints(url)
        all_results[url] = working_endpoints
    
    # Summary
    print("\n" + "=" * 60)
    print("📋 DISCOVERY SUMMARY")
    print("=" * 60)
    
    active_deployments = {url: endpoints for url, endpoints in all_results.items() if endpoints}
    
    if active_deployments:
        print("✅ Found active deployments:")
        for url, endpoints in active_deployments.items():
            print(f"\n🌐 {url}")
            for endpoint in endpoints:
                print(f"   ✅ {endpoint}")
        
        # Recommend the best URL
        best_url = None
        best_score = 0
        for url, endpoints in active_deployments.items():
            score = len(endpoints)
            if "/api/honeypot" in endpoints:
                score += 10  # Bonus for having the main API endpoint
            if score > best_score:
                best_score = score
                best_url = url
        
        if best_url:
            print(f"\n🎯 RECOMMENDED URL: {best_url}")
            print("   Use this URL for your evaluation tests!")
            
            # Create updated test script
            print(f"\n📝 To test this deployment, update your test scripts with:")
            print(f'   BASE_URL = "{best_url}"')
    else:
        print("❌ No active deployments found!")
        print("\n🔧 Troubleshooting steps:")
        print("1. Check if your Railway deployment is running")
        print("2. Verify the deployment URL in Railway dashboard")
        print("3. Check Railway logs for startup errors")
        print("4. Ensure environment variables are set correctly")

if __name__ == "__main__":
    main()