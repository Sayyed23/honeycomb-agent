from fastapi.testclient import TestClient
from app.main import app
from app.core.config import settings
import os

# Ensure we use the TestClient
client = TestClient(app)

def test_health_check():
    print("Testing /health endpoint...")
    response = client.get("/health")
    if response.status_code == 200:
        print("PASS: Health check successful")
        print(response.json())
    else:
        print(f"FAIL: Health check failed {response.status_code}")

def test_scam_detection_flow():
    print("\nTesting /api/v1/honeypot/message endpoint (Scam Detection)...")
    
    # Mock API Key if needed or use default from settings (test-secret-key)
    api_key = settings.API_KEY
    headers = {"x-api-key": api_key}
    
    # Payload similar to GUVI spec
    payload = {
        "sessionId": "test-session-12345",
        "message": {
            "sender": "scammer",
            "text": "Your account is BLOCKED. Click here immediately: http://scam.com/login",
            "timestamp": "2024-01-01T10:00:00Z"
        },
        "conversationHistory": [],
        "metadata": {"channel": "SMS"}
    }
    
    try:
        response = client.post("/api/v1/honeypot/message", json=payload, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            print("PASS: API responded 200 OK")
            print(f"Reply: {data.get('reply')}")
        else:
            print(f"FAIL: API Error {response.status_code}")
            print(response.text)
            
    except Exception as e:
        print(f"FAIL: Exception during request: {e}")

if __name__ == "__main__":
    test_health_check()
    test_scam_detection_flow()
