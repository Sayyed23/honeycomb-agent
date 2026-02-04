
import requests
import json

url = "https://vertie-subcerebellar-pok.ngrok-free.dev/api/honeypot"
headers = {
    "x-api-key": "iR3Prglodfd2xKOCsKa7eNK6kFVKMNHOpzQmfDD6wPs",
    "Content-Type": "application/json"
}
data = {
    "sessionId": "portal-test-new-schema",
    "message": {
        "sender": "scammer",
        "text": "Your bank account will be blocked today. Verify immediately.",
        "timestamp": "2026-02-04T19:40:00Z"
    },
    "conversationHistory": [],
    "metadata": {
        "channel": "SMS",
        "language": "en",
        "locale": "IN"
    }
}

print(f"Sending POST request to {url}...")
try:
    response = requests.post(url, headers=headers, json=data)
    print(f"Status Code: {response.status_code}")
    print(f"Response Text: {response.text}")
    print("Response Body:")
    print(json.dumps(response.json(), indent=2))
except Exception as e:
    print(f"Error: {e}")
