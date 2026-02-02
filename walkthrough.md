# Agentic Honeypot (SentinelHP) - Walkthrough

We have successfully implemented the **Agentic Honeypot** backend, a system designed to autonomously engage with scammers and extract intelligence.

## 🚀 Features Implemented

### 1. **Core API Engine** (`app/api/v1/honeypot.py`)
- **Ingress Endpoint**: `POST /api/v1/honeypot/message` receives messages from various channels (SMS, WhatsApp).
- **Session Management**: Automatically creates or updates sessions, maintaining conversation history in PostgreSQL (or SQLite for dev).
- **Turn Management**: Handles multi-turn conversations and enforces turn limits (default: 16 turns).

### 2. **Intelligence Layer**
- **Scam Detection**: `ScamDetector` analyzes urgency, keywords, and patterns to assign a **Risk Score**.
- **Entity Extraction**: `IntelligenceExtractor` identifies:
    - UPI IDs (`abc@bank`)
    - Phone Numbers (`+91...`)
    - Phishing Links (`http://...`)
    - Bank Accounts
- **LLM Integration**: **AgentOrchestrator** uses **Google Gemini** to generate context-aware, persona-based responses (Naive, Average, Skeptical).

### 3. **Safety & Reporting**
- **Safety Guardrails**: `SafetyService` filters agent outputs to prevent PII leakage.
- **Evaluation Callback**: `EvaluationCallback` sends a final JSON report to the GUVI endpoint upon session completion or termination.
- **Emergency Stop**: `POST /api/v1/honeypot/emergency-stop/{session_id}` kills a session immediately.

### 4. **Dashboard** (`app/templates/dashboard.html`)
- **Visualize Session**: `GET /dashboard/session/{session_id}` renders a clean HTML view of the conversation, risk score, and extracted entities.

---

## 🛠️ How to Run

### 1. **Prerequisites**
- Python 3.11+
- Google Gemini API Key

### 2. **Setup**
```bash
# Install dependencies
pip install -r requirements.txt

# Create .env file
echo "GOOGLE_API_KEY=your_key_here" > .env
```

### 3. **Run Application**
```bash
uvicorn app.main:app --reload
```
API will be available at `http://localhost:8000`.

### 4. **Run via Docker**
```bash
docker build -t honeypot .
docker run -p 8000:8000 -e GOOGLE_API_KEY=your_key honeypot
```

### 5. **Testing**
Run the integration test script:
```bash
python -m tests.test_integration
```

---

## 🧪 API Usage

**Send a Message:**
`POST /api/v1/honeypot/message`
Headers: `x-api-key: test-secret-key`
```json
{
  "sessionId": "demo-1",
  "message": {
    "sender": "scammer",
    "text": "Your account is blocked! Click here: http://bit.ly/fake"
  }
}
```

**View Dashboard:**
Open `http://localhost:8000/dashboard/session/demo-1` in your browser.
