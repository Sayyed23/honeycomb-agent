# Deployment & Evaluation Readiness Guide

## Quick Start

### 1. Test Locally First
```bash
# Start your local server
python start.py

# In another terminal, test locally
python test_local_evaluation.py
```

### 2. Deploy to Railway
```bash
# If you have Railway CLI installed
railway login
railway up

# Or push to your connected Git repository
git add .
git commit -m "Ready for evaluation"
git push origin main
```

### 3. Test Deployed Version
```bash
# Update the URL in the test script and run
python test_deployment_quick.py
```

## Evaluation Requirements Checklist

### ✅ Multiple Requests Reliability
- **Requirement**: Handle multiple concurrent requests without failures
- **Test**: 20+ concurrent requests with >95% success rate
- **Current Status**: Test with `test_deployment_quick.py`

### ✅ Correct JSON Response Format
- **Requirement**: Return proper JSON with required fields
- **Expected Format**:
  ```json
  {
    "status": "success",
    "reply": "AI-generated response"
  }
  ```
- **Test**: Validates all responses have `status` and `reply` fields

### ✅ Low Latency
- **Requirement**: Fast response times
- **Target**: <5 seconds average response time
- **Test**: Measures latency for all requests

### ✅ Proper Error Handling
- **Requirement**: Return appropriate HTTP status codes for errors
- **Test Cases**:
  - Missing API key → 401 Unauthorized
  - Invalid API key → 401 Unauthorized  
  - Missing required fields → 422 Unprocessable Entity
  - Invalid JSON → 400 Bad Request

## Railway Deployment Troubleshooting

### Issue: 404 Not Found on all endpoints

**Possible Causes:**
1. Deployment failed or is not running
2. Wrong Railway URL
3. Port configuration issue
4. Environment variables not set

**Solutions:**

#### Check Railway Dashboard
1. Go to [railway.app](https://railway.app)
2. Check if your deployment is "Active"
3. Look at the deployment logs for errors
4. Verify the correct domain URL

#### Verify Environment Variables
Make sure these are set in Railway dashboard (not in .env file):
```
ENVIRONMENT=production
GEMINI_API_KEY=""
x_API_KEY=""
API_KEY_SECRET=""
```

#### Redeploy if Needed
```bash
# Using Railway CLI
railway up

# Or using Git (if connected)
git push origin main
```

### Issue: Slow Response Times

**Solutions:**
1. Check Railway logs for performance issues
2. Verify database connections are working
3. Ensure Redis is optional (non-blocking)
4. Check if LLM API calls are timing out

### Issue: 500 Internal Server Error

**Solutions:**
1. Check Railway logs for Python errors
2. Verify all dependencies are in requirements.txt
3. Check database initialization
4. Ensure environment variables are correct

## Test Scripts Overview

### `test_local_evaluation.py`
- Tests your API running locally
- Comprehensive evaluation of all requirements
- Use this first to verify everything works

### `test_deployment_quick.py`
- Tests deployed API on Railway
- Quick evaluation focused on key metrics
- Update BASE_URL to your Railway domain

### `test_evaluation_readiness.py`
- Comprehensive deployment test
- Detailed analysis and reporting
- Async testing for better performance

### `test_deployment_discovery.py`
- Finds your active Railway deployment
- Tests multiple possible URLs
- Helps identify the correct domain

## Current Railway Configuration

Based on your `railway.json`:
- Health check endpoint: `/ready`
- Health check timeout: 60 seconds
- Restart policy: ON_FAILURE
- Max retries: 3

## API Endpoints

Your API should have these endpoints:
- `GET /` - Basic info
- `GET /health` - Detailed health check
- `GET /ready` - Simple ready check (for Railway)
- `POST /api/honeypot` - Main API endpoint
- `GET /docs` - API documentation (if enabled)

## Expected Response Format

### Successful Request
```json
{
  "status": "success",
  "reply": "Why is my account being suspended? I haven't done anything wrong."
}
```

### Error Response
```json
{
  "status": "error",
  "code": 401,
  "message": "Invalid API key"
}
```

## Performance Targets

- **Success Rate**: >95% for concurrent requests
- **Average Latency**: <5 seconds
- **P95 Latency**: <7.5 seconds
- **Error Handling**: >75% of error cases handled correctly

## Final Evaluation Steps

1. **Test Locally**: Run `python test_local_evaluation.py`
2. **Deploy**: Push to Railway or run `railway up`
3. **Verify Deployment**: Check Railway dashboard and logs
4. **Test Deployed**: Run `python test_deployment_quick.py`
5. **Full Evaluation**: Run `python test_evaluation_readiness.py`

## Scoring Criteria

- Health Check: 20 points
- Multiple Requests: 30 points  
- JSON Format: 25 points
- Latency: 15 points
- Error Handling: 10 points

**Total: 100 points**
- 90+: Excellent - Ready for evaluation
- 75-89: Good - Should pass evaluation
- 60-74: Fair - Minor improvements needed
- <60: Needs significant improvement

## Support

If you encounter issues:
1. Check Railway logs first
2. Test locally to isolate deployment issues
3. Verify environment variables
4. Check network connectivity
5. Review error messages in test output