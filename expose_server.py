
import sys
from pyngrok import ngrok
import time

# Check if auth token is needed
ngrok.set_auth_token("39CtUxBHyaC9uahJ2wZUVHLpjfI_55fPAkW6jMCDw6gSFr1QW") 

try:
    # Open a HTTP tunnel on the default port 8000
    public_url = ngrok.connect(8000).public_url
    print(f" * ngrok tunnel \"{public_url}\" -> \"http://127.0.0.1:8000\"")
    print(f" * Honeypot Endpoint: {public_url}/api/honeypot")
    
    # Keep the script running
    while True:
        time.sleep(1)

except Exception as e:
    print(f"Error: {e}")
    print("\nNote: You might need to sign up for ngrok and configure your auth token.")
    print("Run: ngrok config add-authtoken <token>")
