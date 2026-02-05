# Honeypot API Testing Guide

## Fixed Issues

### 1. API Key Configuration
- **Issue**: Environment variable mismatch (`x_api_key` vs `x_API_KEY`)
- **Fix**: Updated `.env` file to use `x_API_KEY=iR3PgIodG2xKOCsKa7eNK6HrVKMNHOpzQmfDD6wPs`

### 2. Model Import Conflicts
- **Issue**: Naming conflict between Pydantic `Message` model and database `Message` model
- **Fix**: Renamed database import to `DBMessage`

### 3. Database Health Check
- **Issue**: Async/sync mismatch in health check function
- **Fix**: Made database health check synchronous

### 4. Deployment Configuration
- **Added**: `railway.json` and `Procfile` for proper Railway deployment
- **Added**: Health check endpoint configuration

## Correct API Endpoints

### Health Check
```
GET https://jt-production-fc5b.up.railway.app/health
```
**Headers**: None required

### Honeypot Endpoint
```
POST https://jt-production-fc5b.up.railway.app/api/honeypot
```

**Headers**:
```
Content-Type: application/json
x-api-key: iR3PgIodG2xKOCsKa7eNK6HrVKMNHOpzQmfDD6wPs
```

## Request Body Formats

### Simple Format (Recommended for testing)
```json
{
  "sessionId": "test-session-123",
  "message": "Hello, I am calling from your bank. There is a problem with your account.",
  "conversationHistory": []
}
```

### Full Format (GUVI evaluation – timestamp as epoch ms)
```json
{
  "sessionId": "wertyu-dfghj-ertyui",
  "message": {
    "sender": "scammer",
    "text": "Your bank account will be blocked today. Verify immediately.",
    "timestamp": 1770005528731
  },
  "conversationHistory": [],
  "metadata": {
    "channel": "SMS",
    "language": "English",
    "locale": "IN"
  }
}
```
Follow-up messages include previous messages in `conversationHistory`. Both epoch ms (number) and ISO string timestamps are accepted.

## Expected Response (GUVI-compliant)
```json
{
  "status": "success",
  "reply": "Why is my account being suspended?"
}
```

## GUVI Final Result Callback (mandatory for evaluation)
When scam intent is detected, the system automatically sends the final result to:
`POST https://hackathon.guvi.in/api/updateHoneyPotFinalResult`

Payload format:
```json
{
  "sessionId": "abc123-session-id",
  "scamDetected": true,
  "totalMessagesExchanged": 18,
  "extractedIntelligence": {
    "bankAccounts": [],
    "upiIds": [],
    "phishingLinks": [],
    "phoneNumbers": [],
    "suspiciousKeywords": []
  },
  "agentNotes": "Summary of scammer behavior"
}
```

## Testing Steps

1. **Test Health Endpoint First**
   - Verify the service is running
   - Should return 200 OK with health status

2. **Test Simple Format**
   - Use the simple JSON format above
   - Include proper headers
   - Should return 200 OK with AI reply

3. **Test Full Format**
   - Use the complete message object format
   - Should also return 200 OK with AI reply

## Common Issues and Solutions

### INVALID_REQUEST_BODY
- **Cause**: Missing required fields or invalid JSON format
- **Solution**: Ensure `message` field is present and JSON is valid

### 401 Unauthorized
- **Cause**: Missing or incorrect API key
- **Solution**: Include `x-api-key` header with exact value

### 404 Not Found
- **Cause**: Wrong endpoint URL
- **Solution**: Use `/api/honeypot` (not just `/honeypot`)

### 500 Internal Server Error
- **Cause**: Server-side issues (database, dependencies)
- **Solution**: Check health endpoint first, may need redeployment

## Testing Tools

### Using the Test Script
```bash
python test_api_locally.py
```

### Using cURL
```bash
# Health check
curl -X GET "https://jt-production-fc5b.up.railway.app/health"

# Honeypot test
curl -X POST "https://jt-production-fc5b.up.railway.app/api/honeypot" \
  -H "Content-Type: application/json" \
  -H "x-api-key: iR3PgIodG2xKOCsKa7eNK6HrVKMNHOpzQmfDD6wPs" \
  -d '{
    "sessionId": "test-session-123",
    "message": "Hello, I am calling from your bank.",
    "conversationHistory": []
  }'
```

### Using Postman/API Tester
1. Set method to POST
2. URL: `https://jt-production-fc5b.up.railway.app/api/honeypot`
3. Headers:
   - `Content-Type: application/json`
   - `x-api-key: iR3PgIodG2xKOCsKa7eNK6HrVKMNHOpzQmfDD6wPs`
4. Body: Use one of the JSON formats above