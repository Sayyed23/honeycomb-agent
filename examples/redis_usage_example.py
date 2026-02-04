"""
Example usage of Redis caching layer and session management.
This demonstrates how the components work together in the honeypot system.
"""

import asyncio
from datetime import datetime
from app.core.redis import redis_manager, cache_manager
from app.core.session_manager import session_manager
from app.core.utils import hash_message


async def demonstrate_redis_usage():
    """Demonstrate Redis caching and session management usage."""
    
    print("=== Redis Caching and Session Management Demo ===\n")
    
    try:
        # Initialize Redis connection
        print("1. Initializing Redis connection...")
        await redis_manager.initialize()
        print("   ✓ Redis connection established\n")
        
        # Test basic caching
        print("2. Testing basic caching operations...")
        
        # Cache a risk score
        message = "Hello, I need your bank details urgently for verification!"
        message_hash = hash_message(message)
        risk_data = {
            "risk_score": 0.85,
            "confidence": 0.92,
            "method": "ml_ensemble",
            "factors": ["financial_keywords", "urgency_indicators"],
            "timestamp": datetime.utcnow().isoformat()
        }
        
        await cache_manager.set_risk_score(message_hash, risk_data)
        cached_risk = await cache_manager.get_risk_score(message_hash)
        print(f"   ✓ Risk score cached and retrieved: {cached_risk['risk_score']}")
        
        # Cache entity validation
        await cache_manager.set_entity_validation("upi", "scammer@paytm", False)
        is_valid = await cache_manager.get_entity_validation("upi", "scammer@paytm")
        print(f"   ✓ Entity validation cached: UPI is valid = {is_valid}")
        
        print()
        
        # Test session management
        print("3. Testing session management...")
        
        session_id = "demo-session-001"
        metadata = {
            "source": "demo",
            "ip_address": "192.168.1.100",
            "user_agent": "Demo Client",
            "language": "en"
        }
        
        # Create session
        session_state = await session_manager.create_session(session_id, metadata)
        print(f"   ✓ Session created: {session_state.session_id}")
        print(f"     Status: {session_state.status.value}")
        print(f"     Created at: {session_state.created_at}")
        
        # Add messages to conversation
        await session_manager.add_message(
            session_id, "user", 
            "Hi, I got a call saying my bank account will be blocked. Can you help?",
            {"timestamp": datetime.utcnow().isoformat()}
        )
        
        await session_manager.add_message(
            session_id, "assistant",
            "I understand your concern. Can you tell me more about this call?",
            {"timestamp": datetime.utcnow().isoformat()}
        )
        
        print("   ✓ Added conversation messages")
        
        # Add risk assessment
        await session_manager.add_risk_assessment(
            session_id, 0.75, 0.88, "rule_based",
            {"bank_keywords": True, "fear_tactics": True}
        )
        print("   ✓ Added risk assessment")
        
        # Activate agent
        await session_manager.activate_agent(session_id, "digitally_naive")
        print("   ✓ Agent activated with persona: digitally_naive")
        
        # Add extracted entity
        await session_manager.add_extracted_entity(
            session_id, "phone", "+91-9876543210", 0.95,
            "Extracted from: 'Call me back at +91-9876543210'"
        )
        print("   ✓ Added extracted entity")
        
        # Retrieve and display session state
        updated_session = await session_manager.get_session(session_id)
        print(f"\n   Session Summary:")
        print(f"   - Total turns: {updated_session.metrics.total_turns}")
        print(f"   - Risk score: {updated_session.metrics.risk_score}")
        print(f"   - Agent activated: {updated_session.metrics.agent_activated}")
        print(f"   - Persona: {updated_session.metrics.persona_type}")
        print(f"   - Messages: {len(updated_session.conversation_history)}")
        print(f"   - Entities: {len(updated_session.extracted_entities)}")
        print(f"   - Risk assessments: {len(updated_session.risk_assessments)}")
        
        print()
        
        # Test conversation context caching
        print("4. Testing conversation context caching...")
        context_summary = (
            "User received suspicious call about bank account blocking. "
            "Showing signs of concern and seeking help. "
            "Potential social engineering attempt detected."
        )
        
        await cache_manager.set_conversation_context(session_id, context_summary)
        cached_context = await cache_manager.get_conversation_context(session_id)
        if cached_context:
            print(f"   ✓ Context cached and retrieved: {cached_context[:50]}...")
        else:
            print("   ✗ Failed to retrieve cached context")        
        print()
        
        # Test session completion
        print("5. Testing session completion...")
        await session_manager.complete_session(session_id)
        
        completed_session = await session_manager.get_session(session_id)
        print(f"   ✓ Session completed")
        print(f"     Status: {completed_session.status.value}")
        print(f"     Duration: {completed_session.metrics.engagement_duration} seconds")
        
        print()
        
        # Test cleanup
        print("6. Testing cleanup operations...")
        
        # Get active sessions before cleanup
        active_sessions = await session_manager.get_active_sessions()
        print(f"   Active sessions before cleanup: {len(active_sessions)}")
        
        # Run cleanup (with 0 hours to clean up completed sessions immediately)
        cleaned_count = await session_manager.cleanup_expired_sessions(max_age_hours=0)
        print(f"   ✓ Cleaned up {cleaned_count} expired sessions")
        
        # Verify session was cleaned up
        cleaned_session = await session_manager.get_session(session_id)
        if cleaned_session is None:
            print("   ✓ Session successfully cleaned up")
        else:
            print("   ! Session still exists (may be due to timing)")
        
        print()
        
        # Test health check
        print("7. Testing health check...")
        health_status = await redis_manager.health_check()
        print(f"   ✓ Redis health check: {'Healthy' if health_status else 'Unhealthy'}")
        
        print("\n=== Demo completed successfully! ===")
        
    except Exception as e:
        print(f"❌ Error during demo: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        # Cleanup
        try:
            await redis_manager.close()
            print("\n✓ Redis connection closed")
        except Exception as e:
            print(f"Error closing Redis: {e}")


async def demonstrate_error_handling():
    """Demonstrate graceful error handling when Redis is unavailable."""
    
    print("\n=== Error Handling Demo (Redis Unavailable) ===\n")
    
    # Try to use cache manager without Redis connection
    print("1. Testing cache operations without Redis connection...")
    
    # These should fail gracefully and return False/None
    success = await cache_manager.set_session_state("test-session", {"test": True})
    print(f"   Set operation result: {success}")
    
    data = await cache_manager.get_session_state("test-session")
    print(f"   Get operation result: {data}")
    
    print("   ✓ Operations failed gracefully without crashing")
    
    print("\n=== Error handling demo completed ===")


if __name__ == "__main__":
    print("Redis Caching and Session Management Example")
    print("=" * 50)
    
    # Run the main demo
    asyncio.run(demonstrate_redis_usage())
    
    # Run error handling demo
    asyncio.run(demonstrate_error_handling())