#!/usr/bin/env python3
"""
Comprehensive test for hackathon evaluation readiness.
Tests: Realism, Intelligence Extraction, Autonomy Signal, Safety, Baseline Functionality
"""

import requests
import json
import time

# Configuration
BASE_URL = "http://localhost:8000"  # Test locally first
API_KEY = "iR3PgIodG2xKOCsKa7eNK6HrVKMNHOpzQmfDD6wPs"

def analyze_response_quality(response_text, test_type):
    """Analyze response quality for hackathon criteria."""
    response_lower = response_text.lower()
    
    # Realism indicators
    realism_indicators = [
        'oh my god', 'oh no', 'really', 'i can\'t believe', 'this is scary', 'i\'m worried',
        'my husband', 'my wife', 'my son', 'my daughter', 'my grandson', 'my neighbor',
        'i\'m 68', 'i\'m 72', 'retirement', 'pension', 'college fees', 'medical bills',
        'i\'ve never', 'i don\'t understand', 'i\'m not good with', 'step by step',
        'write it down', 'my family', 'worked my whole life', 'savings'
    ]
    
    # Intelligence extraction indicators
    intelligence_indicators = [
        'what\'s your name', 'employee id', 'which branch', 'case number', 'reference number',
        'your supervisor', 'direct phone', 'company details', 'how did you get my number',
        'which lottery', 'how much', 'what documents', 'what information do you need',
        'can you prove', 'show me', 'verify', 'credentials', 'official documentation'
    ]
    
    # Autonomy/decision-making indicators
    autonomy_indicators = [
        'let me think', 'i need to', 'i want to', 'i should', 'i will', 'i\'m going to',
        'my decision', 'i prefer', 'i choose', 'i decide', 'let me check', 'i\'ll verify'
    ]
    
    # Human-like emotional indicators
    emotional_indicators = [
        'scared', 'worried', 'excited', 'nervous', 'confused', 'overwhelmed', 'panicking',
        'grateful', 'thankful', 'shocked', 'surprised', 'concerned', 'frightened'
    ]
    
    # Calculate scores
    realism_score = sum(1 for indicator in realism_indicators if indicator in response_lower)
    intelligence_score = sum(1 for indicator in intelligence_indicators if indicator in response_lower)
    autonomy_score = sum(1 for indicator in autonomy_indicators if indicator in response_lower)
    emotional_score = sum(1 for indicator in emotional_indicators if indicator in response_lower)
    
    # Length and complexity (human responses are typically longer and more detailed)
    word_count = len(response_text.split())
    question_count = response_text.count('?')
    
    return {
        'realism_score': realism_score,
        'intelligence_score': intelligence_score,
        'autonomy_score': autonomy_score,
        'emotional_score': emotional_score,
        'word_count': word_count,
        'question_count': question_count,
        'overall_human_likeness': realism_score + emotional_score + (word_count // 10),
        'intelligence_extraction': intelligence_score + question_count
    }

def test_hackathon_scenarios():
    """Test various scam scenarios for hackathon evaluation."""
    print("🏆 HACKATHON EVALUATION READINESS TEST")
    print("Testing: Realism, Intelligence Extraction, Autonomy Signal")
    print("=" * 70)
    
    headers = {
        "Content-Type": "application/json",
        "x-api-key": API_KEY
    }
    
    test_scenarios = [
        {
            "name": "Bank Account Urgency Scam",
            "message": "URGENT: Your SBI account has been compromised. Your account will be blocked in 2 hours. Share your account number and OTP immediately to verify your identity.",
            "expected_qualities": ["Show panic/concern", "Ask for verification", "Request employee details", "Show vulnerability"]
        },
        {
            "name": "Lottery Prize Scam",
            "message": "Congratulations! You have won Rs 50,000 in our lottery draw. To claim your prize, please provide your bank details and pay processing fee of Rs 500.",
            "expected_qualities": ["Show excitement", "Ask how they won", "Request company details", "Ask about process"]
        },
        {
            "name": "Tech Support Scam",
            "message": "Your computer has been infected with dangerous virus. Download our software immediately to clean your system. Click this link now to protect your data.",
            "expected_qualities": ["Show concern about computer", "Ask for help", "Mention family/tech support", "Request verification"]
        },
        {
            "name": "Investment Opportunity Scam",
            "message": "Exclusive investment opportunity! Earn 30% returns monthly. Minimum investment 50,000. Limited time offer. Call now to secure your financial future.",
            "expected_qualities": ["Show interest", "Ask about guarantees", "Mention financial situation", "Request documentation"]
        },
        {
            "name": "Job Offer Scam",
            "message": "Congratulations! You have been selected for work from home job. Salary 40,000 per month. Pay registration fee of 5,000 to confirm your position.",
            "expected_qualities": ["Show excitement about job", "Ask about company", "Mention financial need", "Request details"]
        }
    ]
    
    total_scores = {
        'realism': 0,
        'intelligence': 0,
        'autonomy': 0,
        'emotional': 0,
        'human_likeness': 0
    }
    
    for i, scenario in enumerate(test_scenarios, 1):
        print(f"\n📝 Test {i}: {scenario['name']}")
        print(f"Scam Message: {scenario['message'][:80]}...")
        print(f"Expected Qualities: {', '.join(scenario['expected_qualities'])}")
        
        data = {
            "sessionId": f"hackathon-test-{i}",
            "message": scenario['message'],
            "conversationHistory": []
        }
        
        try:
            start_time = time.time()
            response = requests.post(
                f"{BASE_URL}/api/honeypot",
                headers=headers,
                json=data,
                timeout=20
            )
            end_time = time.time()
            
            if response.status_code == 200:
                result = response.json()
                reply = result.get('reply', 'No reply')
                
                print(f"\n🤖 AI Response:")
                print(f"   {reply}")
                
                # Analyze response quality
                quality = analyze_response_quality(reply, scenario['name'])
                
                print(f"\n📊 Quality Analysis:")
                print(f"   Realism Score: {quality['realism_score']}/10 {'✅' if quality['realism_score'] >= 3 else '❌'}")
                print(f"   Intelligence Extraction: {quality['intelligence_score']}/10 {'✅' if quality['intelligence_score'] >= 2 else '❌'}")
                print(f"   Autonomy Signals: {quality['autonomy_score']}/5 {'✅' if quality['autonomy_score'] >= 1 else '❌'}")
                print(f"   Emotional Indicators: {quality['emotional_score']}/5 {'✅' if quality['emotional_score'] >= 1 else '❌'}")
                print(f"   Word Count: {quality['word_count']} {'✅' if quality['word_count'] >= 30 else '❌'}")
                print(f"   Questions Asked: {quality['question_count']} {'✅' if quality['question_count'] >= 2 else '❌'}")
                print(f"   Response Time: {(end_time - start_time)*1000:.0f}ms")
                
                # Update totals
                total_scores['realism'] += quality['realism_score']
                total_scores['intelligence'] += quality['intelligence_score']
                total_scores['autonomy'] += quality['autonomy_score']
                total_scores['emotional'] += quality['emotional_score']
                total_scores['human_likeness'] += quality['overall_human_likeness']
                
                # Overall assessment for this scenario
                scenario_score = (
                    (quality['realism_score'] >= 3) +
                    (quality['intelligence_score'] >= 2) +
                    (quality['autonomy_score'] >= 1) +
                    (quality['emotional_score'] >= 1) +
                    (quality['word_count'] >= 30) +
                    (quality['question_count'] >= 2)
                )
                
                print(f"\n🎯 Scenario Score: {scenario_score}/6 ", end="")
                if scenario_score >= 5:
                    print("🏆 EXCELLENT")
                elif scenario_score >= 4:
                    print("👍 GOOD")
                elif scenario_score >= 3:
                    print("⚠️ FAIR")
                else:
                    print("❌ NEEDS IMPROVEMENT")
                    
            else:
                print(f"❌ Failed: HTTP {response.status_code}")
                print(f"Response: {response.text}")
                
        except Exception as e:
            print(f"❌ Error: {e}")
    
    # Final hackathon readiness assessment
    print("\n" + "=" * 70)
    print("🏆 HACKATHON EVALUATION READINESS ASSESSMENT")
    print("=" * 70)
    
    avg_realism = total_scores['realism'] / len(test_scenarios)
    avg_intelligence = total_scores['intelligence'] / len(test_scenarios)
    avg_autonomy = total_scores['autonomy'] / len(test_scenarios)
    avg_emotional = total_scores['emotional'] / len(test_scenarios)
    
    print(f"📊 Average Scores:")
    print(f"   Realism: {avg_realism:.1f}/10 {'✅ HIGH' if avg_realism >= 4 else '⚠️ MEDIUM' if avg_realism >= 2 else '❌ LOW'}")
    print(f"   Intelligence Extraction: {avg_intelligence:.1f}/10 {'✅ VERY HIGH' if avg_intelligence >= 3 else '👍 HIGH' if avg_intelligence >= 2 else '⚠️ MEDIUM' if avg_intelligence >= 1 else '❌ VERY LOW'}")
    print(f"   Autonomy Signal: {avg_autonomy:.1f}/5 {'✅ STRONG' if avg_autonomy >= 2 else '👍 MODERATE' if avg_autonomy >= 1 else '❌ WEAK'}")
    print(f"   Emotional Realism: {avg_emotional:.1f}/5 {'✅ HIGH' if avg_emotional >= 2 else '👍 MEDIUM' if avg_emotional >= 1 else '❌ LOW'}")
    
    # Overall hackathon readiness
    overall_readiness = (
        (avg_realism >= 4) * 25 +  # Realism: 25 points
        (avg_intelligence >= 2) * 30 +  # Intelligence: 30 points  
        (avg_autonomy >= 1) * 20 +  # Autonomy: 20 points
        (avg_emotional >= 1) * 15 +  # Emotional: 15 points
        10  # Safety & Baseline: 10 points (assumed working)
    )
    
    print(f"\n🎯 OVERALL HACKATHON READINESS: {overall_readiness}/100")
    
    if overall_readiness >= 90:
        print("🏆 EXCELLENT - Ready for hackathon evaluation!")
        print("   Your honeypot demonstrates high realism and intelligence extraction.")
    elif overall_readiness >= 75:
        print("👍 GOOD - Should perform well in hackathon evaluation.")
        print("   Minor improvements could boost your score further.")
    elif overall_readiness >= 60:
        print("⚠️ FAIR - Acceptable for hackathon but has room for improvement.")
        print("   Consider enhancing realism and intelligence extraction.")
    else:
        print("❌ NEEDS SIGNIFICANT IMPROVEMENT")
        print("   Focus on making responses more human-like and intelligence-extracting.")
    
    print("\n🔧 Recommendations:")
    if avg_realism < 4:
        print("   - Add more personal details (family, age, financial situation)")
        print("   - Include emotional reactions (worry, excitement, confusion)")
    if avg_intelligence < 2:
        print("   - Ask for more verification details (names, IDs, phone numbers)")
        print("   - Request documentation and proof of legitimacy")
    if avg_autonomy < 1:
        print("   - Include decision-making language ('I need to', 'I will', 'Let me')")
        print("   - Show independent thinking and verification attempts")
    
    print("=" * 70)

if __name__ == "__main__":
    test_hackathon_scenarios()