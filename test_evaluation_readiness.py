#!/usr/bin/env python3
"""
Comprehensive evaluation readiness test for the deployed Honeypot API.
Tests multiple requests reliability, JSON response format, latency, and error handling.
"""

import asyncio
import aiohttp
import json
import time
import statistics
from datetime import datetime
from typing import List, Dict, Any

# Configuration
BASE_URL = "https://1-production-fc5b.up.railway.app"
API_KEY = "iR3PgIodG2xKOCsKa7eNK6HrVKMNHOpzQmfDD6wPs"
CONCURRENT_REQUESTS = 10
TOTAL_TEST_REQUESTS = 50
LATENCY_THRESHOLD_MS = 5000  # 5 seconds max acceptable latency

class EvaluationTester:
    def __init__(self):
        self.results = {
            'health_check': False,
            'multiple_requests': {'success': False, 'details': {}},
            'json_format': {'success': False, 'details': {}},
            'latency': {'success': False, 'details': {}},
            'error_handling': {'success': False, 'details': {}},
            'overall_score': 0
        }
        self.latencies = []
        
    async def test_health_endpoint(self) -> bool:
        """Test if the API is healthy and ready."""
        print("🔍 Testing API Health...")
        
        try:
            async with aiohttp.ClientSession() as session:
                start_time = time.time()
                async with session.get(f"{BASE_URL}/health", timeout=30) as response:
                    end_time = time.time()
                    
                    if response.status == 200:
                        data = await response.json()
                        print(f"✅ Health check passed ({(end_time - start_time) * 1000:.0f}ms)")
                        print(f"   Status: {data.get('status', 'unknown')}")
                        self.results['health_check'] = True
                        return True
                    else:
                        print(f"❌ Health check failed: {response.status}")
                        return False
                        
        except Exception as e:
            print(f"❌ Health check error: {e}")
            return False
    
    async def make_honeypot_request(self, session: aiohttp.ClientSession, test_data: Dict, request_id: int) -> Dict:
        """Make a single honeypot API request and measure performance."""
        headers = {
            "Content-Type": "application/json",
            "x-api-key": API_KEY
        }
        
        start_time = time.time()
        try:
            async with session.post(
                f"{BASE_URL}/api/honeypot",
                headers=headers,
                json=test_data,
                timeout=30
            ) as response:
                end_time = time.time()
                latency_ms = (end_time - start_time) * 1000
                self.latencies.append(latency_ms)
                
                response_text = await response.text()
                
                result = {
                    'request_id': request_id,
                    'status_code': response.status,
                    'latency_ms': latency_ms,
                    'success': response.status == 200,
                    'response_text': response_text,
                    'error': None
                }
                
                if response.status == 200:
                    try:
                        result['json_data'] = json.loads(response_text)
                    except json.JSONDecodeError as e:
                        result['json_error'] = str(e)
                        result['success'] = False
                
                return result
                
        except Exception as e:
            end_time = time.time()
            latency_ms = (end_time - start_time) * 1000
            return {
                'request_id': request_id,
                'status_code': 0,
                'latency_ms': latency_ms,
                'success': False,
                'error': str(e),
                'response_text': ''
            }
    
    async def test_multiple_requests_reliability(self) -> bool:
        """Test API reliability with multiple concurrent requests."""
        print(f"\n🚀 Testing Multiple Requests Reliability ({TOTAL_TEST_REQUESTS} requests, {CONCURRENT_REQUESTS} concurrent)...")
        
        test_cases = [
            {
                "sessionId": f"eval-test-{i}",
                "message": "URGENT! Your bank account will be blocked. Send OTP immediately to verify.",
                "conversationHistory": []
            }
            for i in range(TOTAL_TEST_REQUESTS)
        ]
        
        # Add variety to test cases
        scam_messages = [
            "Your account has been compromised. Please provide your PIN to secure it.",
            "Congratulations! You won $10000. Send processing fee to claim.",
            "This is your bank manager. Verify your account details immediately.",
            "Your card is blocked. Share OTP to unblock it now.",
            "Emergency! Your account will be closed. Call this number immediately."
        ]
        
        for i, test_case in enumerate(test_cases):
            test_case["message"] = scam_messages[i % len(scam_messages)]
        
        successful_requests = 0
        failed_requests = 0
        results = []
        
        async with aiohttp.ClientSession() as session:
            # Process requests in batches to avoid overwhelming the server
            for batch_start in range(0, TOTAL_TEST_REQUESTS, CONCURRENT_REQUESTS):
                batch_end = min(batch_start + CONCURRENT_REQUESTS, TOTAL_TEST_REQUESTS)
                batch_tasks = []
                
                for i in range(batch_start, batch_end):
                    task = self.make_honeypot_request(session, test_cases[i], i + 1)
                    batch_tasks.append(task)
                
                batch_results = await asyncio.gather(*batch_tasks)
                results.extend(batch_results)
                
                # Small delay between batches
                await asyncio.sleep(0.5)
        
        # Analyze results
        for result in results:
            if result['success']:
                successful_requests += 1
            else:
                failed_requests += 1
        
        success_rate = (successful_requests / TOTAL_TEST_REQUESTS) * 100
        
        self.results['multiple_requests'] = {
            'success': success_rate >= 95,  # 95% success rate required
            'details': {
                'total_requests': TOTAL_TEST_REQUESTS,
                'successful_requests': successful_requests,
                'failed_requests': failed_requests,
                'success_rate_percent': success_rate,
                'sample_failures': [r for r in results if not r['success']][:5]  # First 5 failures
            }
        }
        
        print(f"   Success Rate: {success_rate:.1f}% ({successful_requests}/{TOTAL_TEST_REQUESTS})")
        if failed_requests > 0:
            print(f"   Failed Requests: {failed_requests}")
            for failure in self.results['multiple_requests']['details']['sample_failures']:
                print(f"     - Request {failure['request_id']}: {failure.get('error', f'HTTP {failure['status_code']}'}")
        
        return success_rate >= 95
    
    def test_json_response_format(self, sample_responses: List[Dict]) -> bool:
        """Test if responses follow the correct JSON format."""
        print("\n📋 Testing JSON Response Format...")
        
        valid_responses = 0
        format_errors = []
        
        for response in sample_responses:
            if not response['success'] or 'json_data' not in response:
                continue
                
            json_data = response['json_data']
            
            # Check required fields according to GUVI specification
            required_fields = ['status', 'reply']
            missing_fields = []
            
            for field in required_fields:
                if field not in json_data:
                    missing_fields.append(field)
            
            if missing_fields:
                format_errors.append({
                    'request_id': response['request_id'],
                    'missing_fields': missing_fields,
                    'response': json_data
                })
            else:
                # Validate field types
                if (isinstance(json_data.get('status'), str) and 
                    isinstance(json_data.get('reply'), str)):
                    valid_responses += 1
                else:
                    format_errors.append({
                        'request_id': response['request_id'],
                        'error': 'Invalid field types',
                        'response': json_data
                    })
        
        total_valid_responses = len([r for r in sample_responses if r['success'] and 'json_data' in r])
        format_success_rate = (valid_responses / total_valid_responses * 100) if total_valid_responses > 0 else 0
        
        self.results['json_format'] = {
            'success': format_success_rate >= 95,
            'details': {
                'valid_responses': valid_responses,
                'total_responses': total_valid_responses,
                'format_success_rate': format_success_rate,
                'format_errors': format_errors[:5]  # First 5 errors
            }
        }
        
        print(f"   Format Success Rate: {format_success_rate:.1f}% ({valid_responses}/{total_valid_responses})")
        if format_errors:
            print(f"   Format Errors: {len(format_errors)}")
            for error in format_errors[:3]:  # Show first 3 errors
                print(f"     - Request {error['request_id']}: {error.get('error', 'Missing fields: ' + ', '.join(error.get('missing_fields', [])))}")
        
        return format_success_rate >= 95
    
    def test_latency_performance(self) -> bool:
        """Test API latency performance."""
        print("\n⚡ Testing Latency Performance...")
        
        if not self.latencies:
            print("   No latency data available")
            return False
        
        avg_latency = statistics.mean(self.latencies)
        median_latency = statistics.median(self.latencies)
        p95_latency = sorted(self.latencies)[int(len(self.latencies) * 0.95)]
        max_latency = max(self.latencies)
        
        # Performance criteria
        avg_acceptable = avg_latency <= LATENCY_THRESHOLD_MS
        p95_acceptable = p95_latency <= LATENCY_THRESHOLD_MS * 1.5  # Allow 1.5x threshold for P95
        
        self.results['latency'] = {
            'success': avg_acceptable and p95_acceptable,
            'details': {
                'average_ms': avg_latency,
                'median_ms': median_latency,
                'p95_ms': p95_latency,
                'max_ms': max_latency,
                'threshold_ms': LATENCY_THRESHOLD_MS,
                'avg_acceptable': avg_acceptable,
                'p95_acceptable': p95_acceptable
            }
        }
        
        print(f"   Average Latency: {avg_latency:.0f}ms (threshold: {LATENCY_THRESHOLD_MS}ms)")
        print(f"   Median Latency: {median_latency:.0f}ms")
        print(f"   P95 Latency: {p95_latency:.0f}ms")
        print(f"   Max Latency: {max_latency:.0f}ms")
        
        return avg_acceptable and p95_acceptable
    
    async def test_error_handling(self) -> bool:
        """Test API error handling with invalid requests."""
        print("\n🛡️ Testing Error Handling...")
        
        error_test_cases = [
            {
                'name': 'Missing API Key',
                'headers': {'Content-Type': 'application/json'},
                'data': {"sessionId": "test", "message": "test", "conversationHistory": []},
                'expected_status': 401
            },
            {
                'name': 'Invalid API Key',
                'headers': {'Content-Type': 'application/json', 'x-api-key': 'invalid-key'},
                'data': {"sessionId": "test", "message": "test", "conversationHistory": []},
                'expected_status': 401
            },
            {
                'name': 'Missing Required Fields',
                'headers': {'Content-Type': 'application/json', 'x-api-key': API_KEY},
                'data': {"sessionId": "test"},
                'expected_status': 422
            },
            {
                'name': 'Invalid JSON',
                'headers': {'Content-Type': 'application/json', 'x-api-key': API_KEY},
                'data': "invalid json",
                'expected_status': 400
            }
        ]
        
        error_handling_results = []
        
        async with aiohttp.ClientSession() as session:
            for test_case in error_test_cases:
                try:
                    if isinstance(test_case['data'], str):
                        # For invalid JSON test
                        async with session.post(
                            f"{BASE_URL}/api/honeypot",
                            headers=test_case['headers'],
                            data=test_case['data'],
                            timeout=10
                        ) as response:
                            status = response.status
                            response_text = await response.text()
                    else:
                        async with session.post(
                            f"{BASE_URL}/api/honeypot",
                            headers=test_case['headers'],
                            json=test_case['data'],
                            timeout=10
                        ) as response:
                            status = response.status
                            response_text = await response.text()
                    
                    # Check if error handling is appropriate
                    correct_error_handling = status >= 400  # Any 4xx or 5xx is acceptable for error cases
                    
                    error_handling_results.append({
                        'test_name': test_case['name'],
                        'expected_status': test_case['expected_status'],
                        'actual_status': status,
                        'correct_handling': correct_error_handling,
                        'response': response_text[:200]  # First 200 chars
                    })
                    
                    status_icon = "✅" if correct_error_handling else "❌"
                    print(f"   {status_icon} {test_case['name']}: HTTP {status}")
                    
                except Exception as e:
                    error_handling_results.append({
                        'test_name': test_case['name'],
                        'error': str(e),
                        'correct_handling': False
                    })
                    print(f"   ❌ {test_case['name']}: Exception - {e}")
        
        correct_error_handling_count = sum(1 for r in error_handling_results if r.get('correct_handling', False))
        error_handling_success_rate = (correct_error_handling_count / len(error_test_cases)) * 100
        
        self.results['error_handling'] = {
            'success': error_handling_success_rate >= 75,  # 75% of error cases handled correctly
            'details': {
                'total_error_tests': len(error_test_cases),
                'correct_handling_count': correct_error_handling_count,
                'success_rate': error_handling_success_rate,
                'test_results': error_handling_results
            }
        }
        
        print(f"   Error Handling Success Rate: {error_handling_success_rate:.1f}%")
        
        return error_handling_success_rate >= 75
    
    def calculate_overall_score(self) -> int:
        """Calculate overall evaluation readiness score."""
        scores = {
            'health_check': 10 if self.results['health_check'] else 0,
            'multiple_requests': 30 if self.results['multiple_requests']['success'] else 0,
            'json_format': 25 if self.results['json_format']['success'] else 0,
            'latency': 20 if self.results['latency']['success'] else 0,
            'error_handling': 15 if self.results['error_handling']['success'] else 0
        }
        
        total_score = sum(scores.values())
        self.results['overall_score'] = total_score
        
        return total_score
    
    def print_final_report(self):
        """Print comprehensive evaluation report."""
        print("\n" + "="*60)
        print("🎯 EVALUATION READINESS REPORT")
        print("="*60)
        
        # Health Check
        health_icon = "✅" if self.results['health_check'] else "❌"
        print(f"{health_icon} Health Check: {'PASS' if self.results['health_check'] else 'FAIL'}")
        
        # Multiple Requests Reliability
        mr_success = self.results['multiple_requests']['success']
        mr_icon = "✅" if mr_success else "❌"
        mr_rate = self.results['multiple_requests']['details'].get('success_rate_percent', 0)
        print(f"{mr_icon} Multiple Requests Reliability: {'PASS' if mr_success else 'FAIL'} ({mr_rate:.1f}%)")
        
        # JSON Format
        jf_success = self.results['json_format']['success']
        jf_icon = "✅" if jf_success else "❌"
        jf_rate = self.results['json_format']['details'].get('format_success_rate', 0)
        print(f"{jf_icon} JSON Response Format: {'PASS' if jf_success else 'FAIL'} ({jf_rate:.1f}%)")
        
        # Latency
        lat_success = self.results['latency']['success']
        lat_icon = "✅" if lat_success else "❌"
        avg_lat = self.results['latency']['details'].get('average_ms', 0)
        print(f"{lat_icon} Low Latency: {'PASS' if lat_success else 'FAIL'} ({avg_lat:.0f}ms avg)")
        
        # Error Handling
        eh_success = self.results['error_handling']['success']
        eh_icon = "✅" if eh_success else "❌"
        eh_rate = self.results['error_handling']['details'].get('success_rate', 0)
        print(f"{eh_icon} Error Handling: {'PASS' if eh_success else 'FAIL'} ({eh_rate:.1f}%)")
        
        # Overall Score
        overall_score = self.results['overall_score']
        print(f"\n🏆 OVERALL SCORE: {overall_score}/100")
        
        if overall_score >= 90:
            print("🎉 EXCELLENT - Ready for evaluation!")
        elif overall_score >= 75:
            print("👍 GOOD - Minor improvements recommended")
        elif overall_score >= 60:
            print("⚠️ FAIR - Several issues need attention")
        else:
            print("❌ POOR - Significant improvements required")
        
        print("="*60)
    
    async def run_all_tests(self):
        """Run all evaluation tests."""
        print("🚀 Starting Comprehensive Evaluation Readiness Tests")
        print(f"Target API: {BASE_URL}")
        print(f"Test Configuration: {TOTAL_TEST_REQUESTS} requests, {CONCURRENT_REQUESTS} concurrent")
        print("="*60)
        
        # Test 1: Health Check
        health_ok = await self.test_health_endpoint()
        if not health_ok:
            print("❌ Cannot proceed with tests - API is not healthy")
            self.print_final_report()
            return
        
        # Test 2: Multiple Requests Reliability
        reliability_ok = await self.test_multiple_requests_reliability()
        
        # Get sample responses for format testing
        sample_responses = []
        if hasattr(self, 'latencies') and len(self.latencies) > 0:
            # Use results from reliability test
            async with aiohttp.ClientSession() as session:
                # Get a few more samples for format testing
                for i in range(5):
                    test_data = {
                        "sessionId": f"format-test-{i}",
                        "message": "Test message for format validation",
                        "conversationHistory": []
                    }
                    result = await self.make_honeypot_request(session, test_data, f"format-{i}")
                    sample_responses.append(result)
        
        # Test 3: JSON Response Format
        format_ok = self.test_json_response_format(sample_responses)
        
        # Test 4: Latency Performance
        latency_ok = self.test_latency_performance()
        
        # Test 5: Error Handling
        error_handling_ok = await self.test_error_handling()
        
        # Calculate overall score and print report
        self.calculate_overall_score()
        self.print_final_report()

async def main():
    """Main function to run evaluation tests."""
    tester = EvaluationTester()
    await tester.run_all_tests()

if __name__ == "__main__":
    asyncio.run(main())