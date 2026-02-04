# Google Gemini LLM Integration

## Overview

This document describes the Google Gemini LLM integration implemented for the Agentic Honeypot API. The integration provides intelligent, persona-consistent response generation with comprehensive safety constraints and fallback mechanisms.

## Architecture

### Core Components

1. **GeminiLLMClient** (`app/core/llm_client.py`)
   - Main LLM client for Google Gemini API integration
   - Handles authentication, request/response processing, and error handling
   - Implements safety constraints and content filtering
   - Provides response caching and fallback mechanisms

2. **PromptTemplate** (`app/core/llm_client.py`)
   - Generates persona-specific prompts for different user types
   - Includes conversation context and safety instructions
   - Supports multi-language prompt generation

3. **SafetyConstraints** (`app/core/llm_client.py`)
   - Defines safety rules and content filtering policies
   - Prevents AI revelation and illegal activity assistance
   - Implements response length and content validation

4. **Conversation Engine Integration** (`app/core/conversation_engine.py`)
   - Integrates LLM client with existing conversation engine
   - Falls back to template-based responses when LLM fails
   - Maintains persona consistency across conversation turns

## Features

### Persona-Specific Prompts

The system generates different prompts based on three persona types:

#### Digitally Naive Persona
- Limited tech knowledge, trusting nature
- Asks for clarification on technical terms
- Shows concern about safety but doesn't know risks
- Uses simple language and basic questions

#### Average User Persona
- Moderate tech literacy, balanced approach
- Shows reasonable caution about information sharing
- Asks clarifying questions to understand situations
- Uses everyday language with some technical awareness

#### Skeptical Persona
- High tech knowledge, highly suspicious
- Demands proof and verification for claims
- Challenges inconsistencies with probing questions
- Uses technical language and knows scam tactics

### Safety Constraints

#### Pre-Generation Safety Checks
- Blocks AI revelation requests ("Are you an AI?")
- Prevents illegal activity assistance
- Filters harmful content requests
- Validates input appropriateness

#### Post-Generation Safety Checks
- Ensures responses don't reveal AI nature
- Blocks inappropriate content generation
- Validates response length limits
- Prevents harmful instruction generation

#### Content Filtering
- Blocks generation of illegal activity guidance
- Prevents personal information sharing requests
- Filters violence and harmful content
- Maintains ethical conversation boundaries

### Error Handling & Fallback

#### Graceful Degradation
- Falls back to template-based responses on LLM failure
- Maintains conversation flow during API outages
- Provides persona-appropriate fallback responses
- Logs errors for monitoring and debugging

#### Retry Logic
- Implements exponential backoff for transient failures
- Retries API calls up to 3 times
- Handles rate limiting and temporary errors
- Fails gracefully after retry exhaustion

### Response Caching

- Caches similar responses to reduce API calls
- 5-minute TTL for cached responses
- MD5-based cache keys for prompt similarity
- Automatic cache cleanup to prevent memory bloat

## Configuration

### Environment Variables

```bash
GEMINI_API_KEY=your_google_gemini_api_key_here
```

### Model Configuration

```python
# Default Gemini configuration
model_name = 'gemini-1.5-pro'
temperature = 0.7
max_output_tokens = 500
top_p = 0.8
top_k = 40
```

### Safety Settings

```python
safety_settings = {
    HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
    HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
    HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
    HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
}
```

## Usage Examples

### Basic Response Generation

```python
from app.core.llm_client import llm_client, LLMRequest
from app.core.persona_manager import PersonaType

# Create request
request = LLMRequest(
    session_id="session-123",
    persona=PersonaType.DIGITALLY_NAIVE,
    message_content="Please provide your bank details",
    conversation_history=[],
    context_metadata={"correlation_id": "req-456"}
)

# Generate response
response = await llm_client.generate_response(request)
print(f"Response: {response.generated_content}")
```

### Conversation Engine Integration

```python
from app.core.conversation_engine import conversation_engine

# Generate persona-consistent response
result = await conversation_engine.generate_response(
    session_id="session-123",
    message_content="I need help with UPI transfer",
    conversation_history=[],
    metadata={"correlation_id": "conv-789"}
)

print(f"Response: {result.response_content}")
print(f"Method: {result.generation_method}")  # "persona_based" or "fallback"
```

### Health Check Integration

```python
from app.core.llm_client import llm_client

# Check LLM service health
is_healthy = await llm_client.health_check()
print(f"LLM service healthy: {is_healthy}")
```

## Monitoring & Logging

### Audit Logging

All LLM operations are logged with structured audit events:

```python
# Automatic audit logging includes:
- Session ID and correlation ID
- Persona used for generation
- Prompt and response lengths
- Processing time and model used
- Safety filtering status
- Error details if applicable
```

### Health Monitoring

The LLM client integrates with the system health check endpoint:

```bash
GET /health
```

Returns LLM service status along with other system components.

### Metrics Collection

Key metrics tracked:
- Response generation time
- API call success/failure rates
- Safety filter activation frequency
- Fallback usage statistics
- Cache hit/miss ratios

## Testing

### Unit Tests

Comprehensive test suite covers:
- Prompt template generation
- Safety constraint validation
- Response caching functionality
- Error handling and fallback behavior
- Conversation engine integration

### Integration Tests

End-to-end tests verify:
- Complete conversation flows
- Persona consistency across turns
- Safety constraint enforcement
- Fallback mechanism reliability

### Demo Script

Run the integration demo:

```bash
python examples/gemini_integration_demo.py
```

## Security Considerations

### API Key Management
- Store API keys securely in environment variables
- Never log or expose API keys in responses
- Rotate keys regularly for security

### Content Safety
- All responses filtered for harmful content
- AI nature never revealed to users
- Illegal activities never assisted or encouraged
- Personal information sharing prevented

### Data Privacy
- No conversation data sent to external services beyond Gemini API
- Response caching uses hashed keys for privacy
- Audit logs exclude sensitive content details

## Performance Optimization

### Response Caching
- Reduces API calls for similar prompts
- 5-minute TTL balances freshness and efficiency
- Automatic cleanup prevents memory issues

### Async Processing
- Non-blocking API calls using async/await
- Concurrent request handling capability
- Timeout handling for long-running requests

### Fallback Strategy
- Template-based responses when LLM unavailable
- Maintains conversation flow during outages
- Persona-appropriate fallback content

## Troubleshooting

### Common Issues

1. **API Key Invalid**
   - Verify GEMINI_API_KEY environment variable
   - Check API key permissions and quotas
   - Ensure key is active and not expired

2. **Response Generation Fails**
   - Check network connectivity to Google APIs
   - Verify safety settings aren't too restrictive
   - Review audit logs for specific error details

3. **Fallback Always Used**
   - Confirm LLM client initialization
   - Check API key validity
   - Verify Gemini service availability

### Debug Mode

Enable debug logging for detailed troubleshooting:

```python
import logging
logging.getLogger('app.core.llm_client').setLevel(logging.DEBUG)
```

## Future Enhancements

### Planned Features
- Multi-model support (GPT-4, Claude, etc.)
- Advanced prompt optimization
- Response quality scoring
- A/B testing for different prompts
- Enhanced caching strategies

### Performance Improvements
- Response streaming for long generations
- Batch processing for multiple requests
- Advanced retry strategies
- Load balancing across multiple API keys

## Conclusion

The Google Gemini LLM integration provides a robust, safe, and efficient foundation for intelligent conversation generation in the Agentic Honeypot API. The implementation prioritizes safety, reliability, and persona consistency while maintaining excellent performance through caching and fallback mechanisms.