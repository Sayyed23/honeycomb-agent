import requests
import json

url = "https://vertie-subcerebellar-pok.ngrok-free.dev/api/honeypot"
headers = {
    "x-api-key": "iR3Prglodfd2xKOCsKa7eNK6kFVKMNHOpzQmfDD6wPs",
    "Content-Type": "application/json"
}

# Sending INVALID data (missing text) to trigger 422
data = {
    "sessionId": "error-test",
    "message": {
        "sender": "scammer",
        "timestamp": "2026-02-04T19:40:00Z"
    }
}

print(f"Sending INVALID POST request to {url}...")
response = requests.post(url, headers=headers, json=data)

print(f"Status Code: {response.status_code}")
print(f"Response Body:\n{json.dumps(response.json(), indent=2)}")
