# Railway Deployment Fix Guide

## 🎯 Issue Identified

Your Railway deployment is working correctly, but the **environment variable `x_API_KEY` is missing or incorrect**.

### Current Status:
- ✅ Railway deployment is running
- ✅ Health endpoint works: `https://1-production-fc5b.up.railway.app/health`
- ✅ API endpoint routing works: `https://1-production-fc5b.up.railway.app/api/honeypot`
- ❌ API key validation fails: Returns HTTP 401 "Invalid API key"

## 🔧 Fix Steps

### Step 1: Set Environment Variables in Railway Dashboard

1. **Go to Railway Dashboard:**
   - Visit [railway.app](https://railway.app)
   - Open your project

2. **Navigate to Variables Tab:**
   - Click on your service/deployment
   - Go to the "Variables" tab

3. **Add Required Environment Variables:**
   ```
   x_API_KEY=iR3PgIodG2xKOCsKa7eNK6HrVKMNHOpzQmfDD6wPs
   ENVIRONMENT=production
   GEMINI_API_KEY=AQ.Ab8RN6IEnV3947SFSsNurw6leoPjLu9f5HNItUtqoF593d5gzA
   API_KEY_SECRET=95a803558aa2ee25732820868663eac100365b95f40e59a76fb1bc9bbab77f8e
   ```

4. **Optional Variables (with defaults):**
   ```
   DATABASE_URL=sqlite:///./test.db
   REDIS_URL=redis://localhost:6379/0
   GUVI_CALLBACK_URL=https://hackathon.guvi.in/api/updateHoneyPotFinalResult
   GUVI_API_KEY=test-guvi-key
   ```

### Step 2: Redeploy

After setting the environment variables, Railway should automatically redeploy. If not:
- Click "Deploy" or "Redeploy"
- Wait for deployment to complete

### Step 3: Test the Fix

Run this command to test:
```bash
python test_railway_https.py
```

Expected result: HTTP 200 with JSON response.

## 🧪 Updated Test Configuration

Since your Railway deployment uses HTTPS, update your test scripts:

### Update BASE_URL in all test files:
```python
BASE_URL = "https://1-production-fc5b.up.railway.app"  # Use HTTPS, not HTTP
```

### Files to update:
- `test_railway_api.py`
- `test_evaluation_readiness.py`
- `test_deployment_quick.py`
- `test_deployment_discovery.py`
- `test_api_locally.py`

## 🎯 Quick Test Command

After fixing the environment variables, run:
```bash
python -c "
import requests
response = requests.post(
    'https://1-production-fc5b.up.railway.app/api/honeypot',
    headers={'Content-Type': 'application/json', 'x-api-key': 'iR3PgIodG2xKOCsKa7eNK6HrVKMNHOpzQmfDD6wPs'},
    json={'sessionId': 'test', 'message': 'test', 'conversationHistory': []},
    timeout=10
)
print(f'Status: {response.status_code}')
print(f'Response: {response.text}')
"
```

Expected output:
```
Status: 200
Response: {"status":"success","reply":"..."}
```

## 🏆 Evaluation Readiness

Once the environment variables are fixed:

1. **Run comprehensive evaluation:**
   ```bash
   python test_evaluation_readiness.py
   ```

2. **Expected results:**
   - Success Rate: >95%
   - JSON Format: Valid
   - Latency: <5 seconds
   - Error Handling: Proper HTTP codes

## 🔍 Troubleshooting

### If it still doesn't work:

1. **Check Railway Logs:**
   - Go to Railway dashboard
   - Check "Logs" tab for errors
   - Look for environment variable loading messages

2. **Verify Environment Variables:**
   - Ensure no typos in variable names
   - Check for extra spaces or characters
   - Verify the API key matches exactly

3. **Force Redeploy:**
   - Make a small change to any file
   - Push to trigger redeploy
   - Or use Railway CLI: `railway up`

### Common Issues:

- **Case sensitivity:** Use `x_API_KEY` (not `X_API_KEY` or `x_api_key`)
- **Spaces:** No leading/trailing spaces in values
- **Quotes:** Don't include quotes around values in Railway dashboard

## 🎉 Success Indicators

When fixed, you should see:
- ✅ HTTP 200 responses from `/api/honeypot`
- ✅ Valid JSON responses with `status` and `reply` fields
- ✅ Proper error handling for invalid requests
- ✅ Fast response times (<5 seconds)

Your API will then be ready for evaluation!