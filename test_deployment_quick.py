#!/usr/bin/env python3
"""
Quick deployment test for evaluation readiness.
Focuses on the core requirements: reliability, JSON format, latency, error handling.
"""

import requests
import json
import time
import concurrent.futures
from datetime import datetime

# Configuration
BASE_URL = "http://1-production-fc5b.up.railway.app"
API_KEY = "iR3PgIodG2xKOCsKa7eNK6HrVKMNHOpzQmfDD6wPs"

def test_single_request(session_id: str, message: str) -> dict:
    """Test a single API request and return results."""
    headers = {
        "Content-Type": "application/json",
        "x-api-key": API_KEY
    }
    
    data = {
        "sessionId": session_id,
        "message": message,
        "conversationHistory": []
    }
    
    start_time = time.time()
    try:
        response = requests.post(
            f"{BASE_URL}/api/honeypot",
            headers=headers,
            json=data,
            timeout=10
        )
        end_time = time.time()
        
        latency_ms = (end_time - start_time) * 1000
        
        result = {
            'session_id': session_id,
            'status_code': response.status_code,
            'latency_ms': latency_ms,
            'success': response.status_code == 200,
            'response_text': response.text
        }
        
        if response.status_code == 200:
            try:
                json_data = response.json()
                result['json_data'] = json_data
                # Check required fields
                result['has_status'] = 'status' in json_data
                result['has_reply'] = 'reply' in json_data
                result['valid_format'] = result['has_status'] and result['has_reply']
            except json.JSONDecodeError:
                result['json_error'] = True
                result['valid_format'] = False
        
        return result
        
    except Exception as e:
        end_time = time.time()
        return {
            'session_id': session_id,
            'status_code': 0,
            'latency_ms': (end_time - start_time) * 1000,
            'success': False,
            'error': str(e),
            'valid_format': False
        }

def test_health():
    """Test health endpoint."""
    print("🔍 Testing Health Endpoint...")
    try:
        response = requests.get(f"{BASE_URL}/health", timeout=10)
        if response.status_code == 200:
            print("✅ Health check passed")
            return True
        else:
            print(f"❌ Health check failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Health check error: {e}")
        return False

def test_multiple_requests():
    """Test multiple requests for reliability."""
    print("\n🚀 Testing Multiple Requests (20 concurrent)...")
    
    test_messages = [
        "URGENT! Your bank account will be blocked. Send OTP immediately.",
        "Congratulations! You won $50000. Pay processing fee to claim.",
        "Your card is blocked. Share OTP to unblock immediately.",
        "This is bank manager. Verify account details now.",
        "Emergency! Account will be closed. Call immediately.",
        "Your account has suspicious activity. Provide PIN to secure.",
        "You have won lottery. Send fee to claim prize.",
        "Bank security alert. Confirm details to prevent closure.",
        "Urgent verification needed. Share card details now.",
        "Account compromised. Immediate action required."
    ]
    
    # Create 20 test requests
    test_requests = []
    for i in range(20):
        session_id = f"eval-test-{i+1}"
        message = test_messages[i % len(test_messages)]
        test_requests.append((session_id, message))
    
    # Execute requests concurrently
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_request = {
            executor.submit(test_single_request, session_id, message): (session_id, message)
            for session_id, message in test_requests
        }
        
        for future in concurrent.futures.as_completed(future_to_request):
            result = future.result()
            results.append(result)
    
    # Analyze results
    successful = sum(1 for r in results if r['success'])
    valid_format = sum(1 for r in results if r.get('valid_format', False))
    latencies = [r['latency_ms'] for r in results if r['success']]
    
    success_rate = (successful / len(results)) * 100
    format_rate = (valid_format / successful) * 100 if successful > 0 else 0
    avg_latency = sum(latencies) / len(latencies) if latencies else 0
    max_latency = max(latencies) if latencies else 0
    
    print(f"   Success Rate: {success_rate:.1f}% ({successful}/{len(results)})")
    print(f"   Valid JSON Format: {format_rate:.1f}% ({valid_format}/{successful})")
    print(f"   Average Latency: {avg_latency:.0f}ms")
    print(f"   Max Latency: {max_latency:.0f}ms")
    
    # Show sample responses
    if successful > 0:
        print("\n📋 Sample Responses:")
        for i, result in enumerate(results[:3]):
            if result['success'] and 'json_data' in result:
                json_data = result['json_data']
                print(f"   {i+1}. Status: {json_data.get('status', 'N/A')}")
                print(f"      Reply: {json_data.get('reply', 'N/A')[:100]}...")
    
    # Show failures if any
    failures = [r for r in results if not r['success']]
    if failures:
        print(f"\n❌ Failed Requests ({len(failures)}):")
        for failure in failures[:3]:  # Show first 3 failures
            error_msg = failure.get('error', f"HTTP {failure['status_code']}")
            print(f"   - {failure['session_id']}: {error_msg}")
    
    return {
        'success_rate': success_rate,
        'format_rate': format_rate,
        'avg_latency': avg_latency,
        'max_latency': max_latency,
        'total_requests': len(results),
        'successful_requests': successful
    }

def test_error_handling():
    """Test error handling."""
    print("\n🛡️ Testing Error Handling...")
    
    error_tests = [
        {
            'name': 'Missing API Key',
            'headers': {'Content-Type': 'application/json'},
            'data': {"sessionId": "test", "message": "test", "conversationHistory": []},
            'should_fail': True
        },
        {
            'name': 'Invalid API Key',
            'headers': {'Content-Type': 'application/json', 'x-api-key': 'invalid'},
            'data': {"sessionId": "test", "message": "test", "conversationHistory": []},
            'should_fail': True
        },
        {
            'name': 'Missing Message Field',
            'headers': {'Content-Type': 'application/json', 'x-api-key': API_KEY},
            'data': {"sessionId": "test", "conversationHistory": []},
            'should_fail': True
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
            
            # For error tests, we expect 4xx status codes
            handled_correctly = response.status_code >= 400
            status_icon = "✅" if handled_correctly else "❌"
            
            print(f"   {status_icon} {test['name']}: HTTP {response.status_code}")
            error_results.append(handled_correctly)
            
        except Exception as e:
            print(f"   ❌ {test['name']}: Exception - {e}")
            error_results.append(False)
    
    error_handling_rate = (sum(error_results) / len(error_results)) * 100
    print(f"   Error Handling Rate: {error_handling_rate:.1f}%")
    
    return error_handling_rate

def main():
    """Main test function."""
    print("🎯 DEPLOYMENT EVALUATION READINESS TEST")
    print(f"Target: {BASE_URL}")
    print("="*50)
    
    # Test health first
    health_ok = test_health()
    if not health_ok:
        print("\n❌ Cannot proceed - API is not healthy")
        return
    
    # Test multiple requests
    reliability_results = test_multiple_requests()
    
    # Test error handling
    error_handling_rate = test_error_handling()
    
    # Final evaluation
    print("\n" + "="*50)
    print("🏆 EVALUATION SUMMARY")
    print("="*50)
    
    # Scoring criteria
    health_score = 20 if health_ok else 0
    reliability_score = min(30, (reliability_results['success_rate'] / 100) * 30)
    format_score = min(25, (reliability_results['format_rate'] / 100) * 25)
    latency_score = 15 if reliability_results['avg_latency'] <= 5000 else 0
    error_score = min(10, (error_handling_rate / 100) * 10)
    
    total_score = health_score + reliability_score + format_score + latency_score + error_score
    
    print(f"✅ Health Check: {health_score}/20")
    print(f"🚀 Reliability: {reliability_score:.1f}/30 ({reliability_results['success_rate']:.1f}%)")
    print(f"📋 JSON Format: {format_score:.1f}/25 ({reliability_results['format_rate']:.1f}%)")
    print(f"⚡ Latency: {latency_score}/15 ({reliability_results['avg_latency']:.0f}ms avg)")
    print(f"🛡️ Error Handling: {error_score:.1f}/10 ({error_handling_rate:.1f}%)")
    
    print(f"\n🎯 TOTAL SCORE: {total_score:.1f}/100")
    
    if total_score >= 90:
        print("🎉 EXCELLENT - Ready for evaluation!")
    elif total_score >= 80:
        print("👍 GOOD - Should pass evaluation")
    elif total_score >= 70:
        print("⚠️ FAIR - Minor issues to address")
    else:
        print("❌ NEEDS IMPROVEMENT - Address issues before evaluation")
    
    print("="*50)

if __name__ == "__main__":
    main()