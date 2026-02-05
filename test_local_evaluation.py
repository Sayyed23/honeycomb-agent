#!/usr/bin/env python3
"""
Local evaluation test - run this first to verify your API works locally,
then use the same tests on the deployed version.
"""

import requests
import json
import time
import concurrent.futures
from datetime import datetime

# Configuration - will test local first, then you can update for Railway
BASE_URL = "https://1-production-fc5b.up.railway.app/"
API_KEY = "iR3PgIodG2xKOCsKa7eNK6HrVKMNHOpzQmfDD6wPs"

def start_local_server():
    """Instructions to start local server."""
    print("🚀 To start your local server, run one of these commands:")
    print("   python start.py")
    print("   python app/main.py")
    print("   uvicorn app.main:app --host 0.0.0.0 --port 8000")
    print("\nThen run this test script again.")
    print("=" * 50)

def test_health():
    """Test health endpoint."""
    print("🔍 Testing Health Endpoints...")
    
    endpoints_to_try = ["/health", "/ready", "/"]
    
    for endpoint in endpoints_to_try:
        try:
            response = requests.get(f"{BASE_URL}{endpoint}", timeout=10)
            if response.status_code == 200:
                print(f"✅ {endpoint} endpoint works: HTTP {response.status_code}")
                try:
                    data = response.json()
                    print(f"   Response: {json.dumps(data, indent=2)[:200]}...")
                except:
                    print(f"   Response: {response.text[:100]}...")
                return True
            else:
                print(f"⚠️ {endpoint} endpoint: HTTP {response.status_code}")
        except requests.exceptions.ConnectionError:
            print(f"❌ {endpoint} endpoint: Connection refused")
        except Exception as e:
            print(f"❌ {endpoint} endpoint: {e}")
    
    return False

def test_single_honeypot_request():
    """Test a single honeypot request."""
    print("\n🍯 Testing Single Honeypot Request...")
    
    headers = {
        "Content-Type": "application/json",
        "x-api-key": API_KEY
    }
    
    data = {
        "sessionId": "eval-test-single",
        "message": "URGENT! Your bank account will be blocked. Send OTP immediately to verify.",
        "conversationHistory": []
    }
    
    try:
        start_time = time.time()
        response = requests.post(
            f"{BASE_URL}/api/honeypot",
            headers=headers,
            json=data,
            timeout=30
        )
        end_time = time.time()
        
        latency_ms = (end_time - start_time) * 1000
        
        print(f"   Status Code: {response.status_code}")
        print(f"   Latency: {latency_ms:.0f}ms")
        
        if response.status_code == 200:
            try:
                json_data = response.json()
                print(f"   ✅ Valid JSON response")
                print(f"   Status: {json_data.get('status', 'N/A')}")
                print(f"   Reply: {json_data.get('reply', 'N/A')[:100]}...")
                
                # Check required fields
                has_status = 'status' in json_data
                has_reply = 'reply' in json_data
                print(f"   Required fields: status={has_status}, reply={has_reply}")
                
                return True
            except json.JSONDecodeError:
                print(f"   ❌ Invalid JSON response")
                print(f"   Response: {response.text[:200]}...")
                return False
        else:
            print(f"   ❌ Request failed")
            print(f"   Response: {response.text[:200]}...")
            return False
            
    except Exception as e:
        print(f"   ❌ Request error: {e}")
        return False

def test_multiple_requests():
    """Test multiple concurrent requests."""
    print("\n🚀 Testing Multiple Concurrent Requests (10 requests)...")
    
    def make_request(request_id):
        headers = {
            "Content-Type": "application/json",
            "x-api-key": API_KEY
        }
        
        data = {
            "sessionId": f"eval-test-{request_id}",
            "message": f"Test message {request_id} - Your account needs verification.",
            "conversationHistory": []
        }
        
        start_time = time.time()
        try:
            response = requests.post(
                f"{BASE_URL}/api/honeypot",
                headers=headers,
                json=data,
                timeout=15
            )
            end_time = time.time()
            
            return {
                'id': request_id,
                'success': response.status_code == 200,
                'status_code': response.status_code,
                'latency_ms': (end_time - start_time) * 1000,
                'response': response.text if response.status_code != 200 else 'OK'
            }
        except Exception as e:
            end_time = time.time()
            return {
                'id': request_id,
                'success': False,
                'status_code': 0,
                'latency_ms': (end_time - start_time) * 1000,
                'response': str(e)
            }
    
    # Execute concurrent requests
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(make_request, i) for i in range(1, 11)]
        results = [future.result() for future in concurrent.futures.as_completed(futures)]
    
    # Analyze results
    successful = sum(1 for r in results if r['success'])
    latencies = [r['latency_ms'] for r in results if r['success']]
    
    success_rate = (successful / len(results)) * 100
    avg_latency = sum(latencies) / len(latencies) if latencies else 0
    max_latency = max(latencies) if latencies else 0
    
    print(f"   Success Rate: {success_rate:.1f}% ({successful}/{len(results)})")
    print(f"   Average Latency: {avg_latency:.0f}ms")
    print(f"   Max Latency: {max_latency:.0f}ms")
    
    # Show failures
    failures = [r for r in results if not r['success']]
    if failures:
        print(f"   Failures ({len(failures)}):")
        for failure in failures[:3]:
            print(f"     - Request {failure['id']}: {failure['response'][:50]}...")
    
    return success_rate >= 90, avg_latency

def test_error_handling():
    """Test error handling."""
    print("\n🛡️ Testing Error Handling...")
    
    error_tests = [
        {
            'name': 'Missing API Key',
            'headers': {'Content-Type': 'application/json'},
            'data': {"sessionId": "test", "message": "test", "conversationHistory": []}
        },
        {
            'name': 'Invalid API Key',
            'headers': {'Content-Type': 'application/json', 'x-api-key': 'invalid'},
            'data': {"sessionId": "test", "message": "test", "conversationHistory": []}
        },
        {
            'name': 'Missing Message',
            'headers': {'Content-Type': 'application/json', 'x-api-key': API_KEY},
            'data': {"sessionId": "test", "conversationHistory": []}
        }
    ]
    
    error_results = []
    for test in error_tests:
        try:
            response = requests.post(
                f"{BASE_URL}/api/honeypot",
                headers=test['headers'],
                json=test['data'],
                timeout=10
            )
            
            # Expect 4xx status codes for errors
            handled_correctly = 400 <= response.status_code < 500
            status_icon = "✅" if handled_correctly else "❌"
            
            print(f"   {status_icon} {test['name']}: HTTP {response.status_code}")
            error_results.append(handled_correctly)
            
        except Exception as e:
            print(f"   ❌ {test['name']}: Exception - {e}")
            error_results.append(False)
    
    error_rate = (sum(error_results) / len(error_results)) * 100
    print(f"   Error Handling Rate: {error_rate:.1f}%")
    
    return error_rate >= 75

def main():
    """Main test function."""
    print("🎯 LOCAL EVALUATION READINESS TEST")
    print(f"Target: {BASE_URL}")
    print("=" * 50)
    
    # Test health
    health_ok = test_health()
    if not health_ok:
        print("\n❌ API is not running locally!")
        start_local_server()
        return
    
    print("✅ API is running locally!")
    
    # Test single request
    single_ok = test_single_honeypot_request()
    if not single_ok:
        print("\n❌ Single request test failed - check your API implementation")
        return
    
    # Test multiple requests
    reliability_ok, avg_latency = test_multiple_requests()
    
    # Test error handling
    error_ok = test_error_handling()
    
    # Final evaluation
    print("\n" + "=" * 50)
    print("🏆 LOCAL EVALUATION SUMMARY")
    print("=" * 50)
    
    health_score = 25 if health_ok else 0
    single_score = 25 if single_ok else 0
    reliability_score = 25 if reliability_ok else 0
    latency_score = 15 if avg_latency <= 5000 else 0
    error_score = 10 if error_ok else 0
    
    total_score = health_score + single_score + reliability_score + latency_score + error_score
    
    print(f"✅ Health Check: {health_score}/25")
    print(f"🍯 Single Request: {single_score}/25")
    print(f"🚀 Reliability: {reliability_score}/25")
    print(f"⚡ Latency: {latency_score}/15 ({avg_latency:.0f}ms avg)")
    print(f"🛡️ Error Handling: {error_score}/10")
    
    print(f"\n🎯 TOTAL SCORE: {total_score}/100")
    
    if total_score >= 90:
        print("🎉 EXCELLENT - Ready for deployment and evaluation!")
        print("\n📝 Next steps:")
        print("1. Deploy to Railway using: railway up")
        print("2. Update the BASE_URL in test scripts to your Railway URL")
        print("3. Run the same tests on the deployed version")
    elif total_score >= 75:
        print("👍 GOOD - Should work for evaluation")
        print("Consider fixing any issues before deployment")
    else:
        print("❌ NEEDS IMPROVEMENT - Fix issues before deployment")
    
    print("=" * 50)

if __name__ == "__main__":
    main()