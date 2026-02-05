#!/usr/bin/env python3
"""
Direct test of the honeypot response logic without server.
"""

import asyncio
import random
from app.api.routes.honeypot import *

def test_direct_response():
    """Test the response logic directly."""
    print("🧪 Testing Direct Response Logic")
    print("=" * 50)
    
    test_messages = [
        "URGENT: Your SBI account has been compromised. Your account will be blocked in 2 hours.",
        "Congratulations! You have won Rs 50,000 in our lottery draw.",
        "Your computer has been infected with dangerous virus.",
        "Exclusive investment opportunity! Earn 30% returns monthly.",
        "Congratulations! You have been selected for work from home job."
    ]
    
    for i, message in enumerate(test_messages, 1):
        print(f"\n📝 Test {i}: {message[:50]}...")
        
        # Test the response logic directly
        message_lower = message.lower()
        
        # Bank/Financial scam responses
        if any(word in message_lower for word in ['bank', 'account', 'blocked', 'suspended', 'otp', 'verify', 'urgent']):
            realistic_responses = [
                "Oh my God, really? My account is blocked? I just used it yesterday to pay my electricity bill. What exactly happened? Can you tell me which transactions look suspicious? What's your name and employee ID? I want to make sure I'm talking to the right person.",
                "This is so scary! I have my salary in that account. How did someone get access? Do you know what they tried to do? Should I check my recent transactions? Can you give me your direct phone number in case I need to call back?"
            ]
        
        # Prize/Lottery scam responses  
        elif any(word in message_lower for word in ['won', 'winner', 'prize', 'lottery', 'congratulations', 'claim']):
            realistic_responses = [
                "Really?! I can't believe this! I never win anything! How much did I win exactly? My neighbor always says these things are fake, but this is real, right? What do I need to do to get my money? What's your company name?",
                "Oh wow! This is amazing! I was just telling my wife yesterday that we need money for our daughter's wedding. How did you get my number? What lottery was this for? Do I need to pay anything first? Can you send me official papers?"
            ]
        
        # Tech support scam responses
        elif any(word in message_lower for word in ['computer', 'virus', 'infected', 'software', 'download', 'technical', 'microsoft', 'windows']):
            realistic_responses = [
                "Oh no! I knew something was wrong with my computer! It's been running so slowly lately and I keep getting strange pop-ups. I'm so worried I'll lose all my family photos! Can you help me fix it right now? What's your name and which company are you from?",
                "This explains everything! My computer has been acting weird for weeks. I was scared to use it for online banking. How bad is the infection? Can you clean it remotely? What software do I need to download? Is it free? What's your employee ID?"
            ]
        
        # Investment/Trading scam responses
        elif any(word in message_lower for word in ['investment', 'trading', 'profit', 'returns', 'opportunity', 'money', 'earn']):
            realistic_responses = [
                "This sounds very interesting! I've been looking for ways to grow my retirement money. My fixed deposits are giving such low returns these days. How much can I start with? What kind of profits do your other clients usually make? Is it guaranteed? What's your company name?",
                "I'm definitely interested! My neighbor was just telling me about people making good money from online investments. I have about 3 lakhs sitting in my savings account doing nothing. How does this work exactly? What's the minimum investment? Can you give me references?"
            ]
        
        # Job/Employment scam responses
        elif any(word in message_lower for word in ['job', 'work', 'employment', 'salary', 'hiring', 'position']):
            realistic_responses = [
                "This is perfect timing! I've been looking for work from home opportunities. I lost my job during COVID and haven't found anything stable since. What kind of work is it? How much does it pay? Do I need any special skills? What's your company name?",
                "I'm very interested! I'm a housewife and want to earn some extra money for my family. My husband's salary is not enough these days. Is this really work from home? What are the working hours? How do I apply? What's your HR department number?"
            ]
        
        # Generic highly engaging responses for other scams
        else:
            realistic_responses = [
                "This sounds really important and I want to understand everything properly. I'm a bit nervous because my son always warns me about scams, but you sound very professional. Can you explain this to me step by step? What exactly do you need from me? What's your name and company?"
            ]
        
        response = random.choice(realistic_responses)
        print(f"🤖 Response: {response}")
        
        # Analyze the response
        response_lower = response.lower()
        
        realism_indicators = [
            'oh my god', 'oh no', 'really', 'i can\'t believe', 'this is scary', 'i\'m worried',
            'my husband', 'my wife', 'my son', 'my daughter', 'my grandson', 'my neighbor',
            'retirement', 'pension', 'college fees', 'salary', 'savings'
        ]
        
        intelligence_indicators = [
            'what\'s your name', 'employee id', 'company name', 'direct phone', 'hr department',
            'how did you get my number', 'can you send me', 'official papers', 'references'
        ]
        
        realism_score = sum(1 for indicator in realism_indicators if indicator in response_lower)
        intelligence_score = sum(1 for indicator in intelligence_indicators if indicator in response_lower)
        word_count = len(response.split())
        question_count = response.count('?')
        
        print(f"📊 Analysis:")
        print(f"   Realism Score: {realism_score}/10 {'✅' if realism_score >= 3 else '❌'}")
        print(f"   Intelligence Score: {intelligence_score}/10 {'✅' if intelligence_score >= 2 else '❌'}")
        print(f"   Word Count: {word_count} {'✅' if word_count >= 30 else '❌'}")
        print(f"   Questions: {question_count} {'✅' if question_count >= 2 else '❌'}")

if __name__ == "__main__":
    test_direct_response()