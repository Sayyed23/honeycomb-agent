# API Authentication and Security

This document describes the authentication and security features implemented for the Agentic Honeypot API.

## Overview

The API implements a comprehensive authentication system with the following features:

- **API Key Authentication**: Secure API key-based authentication with database storage
- **Rate Limiting**: Per-key rate limiting with configurable limits
- **Input Validation**: Comprehensive input sanitization and validation
- **Security Headers**: Standard security headers for all responses
- **Usage Tracking**: Detailed API usage tracking and analytics
- **Request Logging**: Structured logging for all API requests

## API Key Management

### API Key Format

API keys are 32-character URL-safe strings generated using cryptographically secure random number generation:
```

### Key Storage

API keys are stored securely in the database:

- **Hashed Storage**: Keys are hashed using PBKDF2-SHA256 with 100,000 iterations
- **Prefix Indexing**: First 8 characters stored for efficient lookup
- **Metadata**: Name, description, permissions, and usage statistics

### Creating API Keys

Use the provided script to create new API keys:

```bash
# Create a basic API key
python scripts/create_api_key.py create "My API Key"

# Create with custom settings
python scripts/create_api_key.py create "Production Key" \
  --description "Production API access" \
  --rate-limit 5000 \
  --created-by "admin" \
  --expires-days 365
```

### Managing API Keys

```bash
# List all API keys
python scripts/create_api_key.py list

# Deactivate an API key
python scripts/create_api_key.py deactivate abcd1234
```

## Authentication Flow

### 1. Request Authentication

All protected endpoints require the `x-api-key` header:

```http
POST /api/honeypot
Content-Type: application/json
x-api-key: your-api-key-here

{
  "sessionId": "session-123",
  "message": "Hello world"
}
```

### 2. Key Validation Process

1. **Header Extraction**: Extract API key from `x-api-key` header
2. **Prefix Lookup**: Find potential matching keys by prefix
3. **Hash Verification**: Verify full key against stored hash
4. **Expiration Check**: Ensure key hasn't expired
5. **Rate Limit Check**: Verify request is within rate limits

### 3. Response Headers

Successful requests include rate limiting headers:

```http
HTTP/1.1 200 OK
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1640995200
```

## Rate Limiting

### Configuration

Each API key has configurable rate limits:

- **Default Limit**: 1000 requests per hour
- **Fixed Window**: Rate limits reset at the top of each hour
- **Per-Key Limits**: Individual limits per API key- **Per-Key Limits**: Individual limits per API key

### Rate Limit Headers

All responses include rate limit information:

- `X-RateLimit-Limit`: Maximum requests per hour
- `X-RateLimit-Remaining`: Remaining requests in current hour
- `X-RateLimit-Reset`: Unix timestamp when limit resets

### Rate Limit Exceeded

When rate limits are exceeded, the API returns:

```http
HTTP/1.1 429 Too Many Requests
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1640995200

{
  "detail": "Rate limit exceeded"
}
```

## Input Validation and Sanitization

### Request Validation

All requests undergo comprehensive validation:

1. **Content-Type Validation**: Must be `application/json`
2. **JSON Parsing**: Valid JSON structure required
3. **Schema Validation**: Pydantic model validation
4. **Input Sanitization**: XSS and injection prevention

### Sanitization Features

- **HTML Escaping**: All text inputs are HTML-escaped
- **Pattern Removal**: Dangerous patterns (scripts, events) removed
- **Injection Detection**: SQL and command injection detection
- **Length Limits**: Configurable maximum lengths

### Validation Errors

Invalid requests return detailed error information:

```http
HTTP/1.1 400 Bad Request

{
  "message": "Validation error",
  "errors": [
    "sessionId: Session ID contains invalid characters",
    "message: Text too long: 6000 > 5000"
  ]
}
```

## Security Headers

All responses include comprehensive security headers:

```http
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
Referrer-Policy: strict-origin-when-cross-origin
Content-Security-Policy: default-src 'self'; script-src 'none'; object-src 'none';
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

## Usage Tracking

### Detailed Logging

Every API request is logged with:

- **Request Details**: Method, endpoint, headers, body size
- **Response Details**: Status code, response size, processing time
- **Client Information**: IP address, user agent
- **API Key Information**: Key name, usage statistics

### Usage Analytics

The system tracks:

- **Total Requests**: Lifetime request count per key
- **Hourly Usage**: Current hour usage for rate limiting
- **Response Times**: Performance metrics
- **Error Rates**: Success/failure statistics

### Database Schema

Usage data is stored in two tables:

```sql
-- API key metadata
CREATE TABLE api_keys (
    id UUID PRIMARY KEY,
    key_name VARCHAR(100) NOT NULL,
    key_hash BYTEA NOT NULL,
    key_prefix VARCHAR(8) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    rate_limit_per_hour INTEGER DEFAULT 1000,
    usage_count INTEGER DEFAULT 0,
    current_hour_usage INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Detailed usage tracking
CREATE TABLE api_key_usage (
    id UUID PRIMARY KEY,
    api_key_id UUID REFERENCES api_keys(id),
    endpoint VARCHAR(200) NOT NULL,
    method VARCHAR(10) NOT NULL,
    status_code INTEGER NOT NULL,
    client_ip VARCHAR(45),
    request_timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    response_time_ms INTEGER
);
```

## Error Handling

### Authentication Errors

| Status Code | Error | Description |
|-------------|-------|-------------|
| 401 | Missing x-api-key header | No API key provided |
| 403 | Invalid or expired API key | Key not found or expired |
| 429 | Rate limit exceeded | Too many requests |

### Validation Errors

| Status Code | Error | Description |
|-------------|-------|-------------|
| 400 | Validation error | Invalid request format |
| 413 | Request payload too large | Request body exceeds limit |
| 415 | Unsupported Content-Type | Invalid content type |
| 422 | Unprocessable Entity | Pydantic validation failed |

## Security Best Practices

### API Key Security

1. **Secure Storage**: Store keys securely, never in code
2. **Environment Variables**: Use environment variables for keys
3. **Key Rotation**: Regularly rotate API keys
4. **Least Privilege**: Use minimal required permissions

### Request Security

1. **HTTPS Only**: Always use HTTPS in production
2. **Input Validation**: Validate all inputs on client side too
3. **Rate Limiting**: Implement client-side rate limiting
4. **Error Handling**: Don't expose sensitive information in errors

### Example Secure Usage

```python
import os
import requests

# Secure API key storage
API_KEY = os.environ.get('HONEYPOT_API_KEY')
if not API_KEY:
    raise ValueError("API key not found in environment")

# Secure request
response = requests.post(
    'https://api.honeypot.example.com/api/honeypot',
    headers={
        'x-api-key': API_KEY,
        'content-type': 'application/json'
    },
    json={
        'sessionId': 'secure-session-123',
        'message': 'Hello, secure world!'
    },
    timeout=30  # Always set timeouts
)

# Handle rate limiting
if response.status_code == 429:
    retry_after = int(response.headers.get('X-RateLimit-Reset', 0))
    print(f"Rate limited. Retry after: {retry_after}")
```

## Monitoring and Alerting

### Metrics

The system exposes Prometheus metrics:

- `http_requests_total`: Total HTTP requests by method, endpoint, status
- `http_request_duration_seconds`: Request duration histogram
- `api_key_usage_total`: API key usage by key and endpoint
- `rate_limit_exceeded_total`: Rate limit violations

### Alerts

Recommended alerts:

- High error rate (>5% 4xx/5xx responses)
- Rate limit violations (>10 per hour per key)
- Authentication failures (>100 per hour)
- Slow response times (>2 seconds 95th percentile)

## Testing

### Unit Tests

Run authentication tests:

```bash
python -m pytest tests/test_auth.py -v
python -m pytest tests/test_validation.py -v
```

### Integration Tests

Run end-to-end tests:

```bash
python -m pytest tests/test_honeypot_integration.py -v
```

### Load Testing

Test rate limiting and performance:

```bash
# Install load testing tools
pip install locust

# Run load tests
locust -f tests/load_test.py --host=http://localhost:8000
```

## Troubleshooting

### Common Issues

1. **401 Unauthorized**: Check API key header format
2. **403 Forbidden**: Verify API key is active and not expired
3. **429 Rate Limited**: Wait for rate limit reset or increase limits
4. **400 Bad Request**: Check request format and validation

### Debug Mode

Enable debug logging:

```bash
export LOG_LEVEL=DEBUG
python -m uvicorn app.main:app --reload
```

### Health Checks

Monitor system health:

```bash
curl http://localhost:8000/health
```

## Migration Guide

### From Simple Authentication

If migrating from simple API key authentication:

1. **Create Database Tables**: Run Alembic migrations
2. **Generate New Keys**: Create proper API keys in database
3. **Update Clients**: No changes needed for client code
4. **Monitor Usage**: Set up monitoring and alerting

### Database Migration

```bash
# Run migrations
alembic upgrade head

# Create initial API key
python scripts/create_api_key.py create "Initial Key"
```