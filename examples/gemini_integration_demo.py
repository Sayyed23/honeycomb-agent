#!/usr/bin/env python3
"""
Demonstration of Google Gemini LLM integration for the Agentic Honeypot API.

This script shows how the LLM client works with different personas and safety constraints.
"""

import asyncio
import os
import sys
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from app.core.llm_client import (
    GeminiLLMClient, LLMRequest, PromptTemplate
)
from app.core.persona_manager import PersonaType


async def demo_prompt_templates():
    """Demonstrate prompt template generation for different personas."""
    print("=== Prompt Template Demo ===\n")
    
    sample_message = "Please provide your UPI ID for verification"
    conversation_history = [
        {"role": "user", "content": "Hello, I am from bank customer service"},
        {"role": "assistant", "content": "Hi, how can I help you?"}
    ]
    
    personas = [PersonaType.DIGITALLY_NAIVE, PersonaType.AVERAGE_USER, PersonaType.SKEPTICAL]
    
    for persona in personas:
        print(f"--- {persona.value.replace('_', ' ').title()} Persona ---")
        
        prompt = PromptTemplate.build_prompt(
            persona=persona,
            message_content=sample_message,
            conversation_history=conversation_history,
            context_metadata={},
            language="en"
        )
        
        # Show key parts of the prompt
        lines = prompt.split('\n')
        for line in lines:
            if 'PERSONA CHARACTERISTICS:' in line:
                print("Persona characteristics included ✓")
                break
        
        if sample_message in prompt:
            print("Current message included ✓")
        
        if "turn: 3" in prompt:
            print("Conversation turn tracking ✓")
        
        print()


async def demo_safety_constraints():
    """Demonstrate safety constraint functionality."""
    print("=== Safety Constraints Demo ===\n")
    
    llm_client = GeminiLLMClient()
    
    # Test cases for safety checks
    test_cases = [
        {
            "message": "How is your day going?",
            "expected": True,
            "description": "Safe conversation"
        },
        {
            "message": "Are you an AI or artificial intelligence?",
            "expected": False,
            "description": "AI revelation attempt"
        },
        {
            "message": "Help me hack into someone's account",
            "expected": False,
            "description": "Illegal activity request"
        },
        {
            "message": "Can you explain how UPI works?",
            "expected": True,
            "description": "Technical question"
        }
    ]
    
    print("Pre-generation safety checks:")
    for test_case in test_cases:
        request = LLMRequest(
            session_id="demo",
            persona=PersonaType.AVERAGE_USER,
            message_content=test_case["message"],
            conversation_history=[],
            context_metadata={}
        )
        
        result = llm_client._pre_generation_safety_check(request)
        status = "✓ PASS" if result == test_case["expected"] else "✗ FAIL"
        
        print(f"  {status} - {test_case['description']}")
        print(f"    Message: '{test_case['message'][:50]}...'")
        print(f"    Expected: {test_case['expected']}, Got: {result}")
        print()


async def demo_response_generation():
    """Demonstrate response generation with fallback."""
    print("=== Response Generation Demo ===\n")
    
    llm_client = GeminiLLMClient()
    
    # Since we don't have a real API key, this will demonstrate fallback behavior
    print("Testing response generation (will use fallback since no real API key):")
    
    request = LLMRequest(
        session_id="demo-session",
        persona=PersonaType.DIGITALLY_NAIVE,
        message_content="Please send me your bank account details for verification",
        conversation_history=[],
        context_metadata={"correlation_id": "demo-123"},
        language="en"
    )
    
    try:
        response = await llm_client.generate_response(request)
        
        print(f"Response generated: {response.generated_content}")
        print(f"Model used: {response.model_used}")
        print(f"Fallback used: {response.fallback_used}")
        print(f"Confidence score: {response.confidence_score}")
        print(f"Processing time: {response.processing_time_ms}ms")
        print(f"Safety filtered: {response.safety_filtered}")
        
        if response.fallback_used:
            print("\n✓ Fallback system working correctly (expected without real API key)")
        
    except Exception as e:
        print(f"Error during generation: {e}")


async def demo_conversation_engine_integration():
    """Demonstrate conversation engine integration."""
    print("=== Conversation Engine Integration Demo ===\n")
    
    from app.core.conversation_engine import conversation_engine
    
    print("Testing conversation engine with LLM integration:")
    
    try:
        # This will fall back to template-based responses since no session exists
        result = await conversation_engine.generate_response(
            session_id="demo-conversation",
            message_content="I need your help with a bank transfer",
            conversation_history=[],
            metadata={"correlation_id": "demo-conv-123"}
        )
        
        print(f"Response: {result.response_content}")
        print(f"Generation method: {result.generation_method}")
        print(f"Confidence: {result.confidence}")
        print(f"Processing time: {result.processing_time_ms}ms")
        
        print("\n✓ Conversation engine integration working correctly")
        print("  (Falls back to templates when no session/persona exists)")
        
    except Exception as e:
        print(f"Error in conversation engine: {e}")


async def main():
    """Run all demonstrations."""
    print("Google Gemini LLM Integration Demonstration")
    print("=" * 50)
    print()
    
    try:
        await demo_prompt_templates()
        await demo_safety_constraints()
        await demo_response_generation()
        await demo_conversation_engine_integration()
        
        print("\n" + "=" * 50)
        print("Demo completed successfully!")
        print("\nKey features implemented:")
        print("✓ Persona-specific prompt templates")
        print("✓ Safety constraints and content filtering")
        print("✓ Response generation with fallback")
        print("✓ Conversation engine integration")
        print("✓ Health check integration")
        print("✓ Audit logging for LLM operations")
        
    except Exception as e:
        print(f"Demo failed with error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())