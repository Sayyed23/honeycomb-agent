# Agentic Honeypot API: Detailed Technical Specification

**Based on:** Agentic Honeypot PRD (SentinelHP)
**Target:** 2-Day Hackathon Build

## 1. Executive Summary
The Agentic Honeypot (SentinelHP) is a defensive security system designed to autonomously engage scammers via SMS/WhatsApp-styled APIs. It uses AI agents to maintain multi-turn conversations, extracting actionable intelligence (UPI IDs, bank accounts, PhD links) while strictly adhering to ethical safety guidelines. The system reports findings via a mandatory callback to a judging endpoint.

## 2. Technology Stack
*   **Language**: Python 3.11+
*   **Framework**: FastAPI (Async)
*   **Database**: PostgreSQL 15+ (SQLAlchemy 2.0 ORM)
*   **AI Agent**: Google Gemini API (via ADK or direct integration)
*   **HTTP Client**: `httpx` (for callbacks)
*   **Deployment**: Railway / Google Cloud Run / Render

## 3. System Architecture

### 3.1 High-Level Flow
1.  **Ingress**: Receive `POST` request (Scam Message) -> Validate API Key -> Create/Load Session.
2.  **Detection**: layered analysis (Keywords -> Behavioral -> LLM Fallback) -> Assign Risk Score.
3.  **Decision**: If Risk > 0.75 & Session Active -> Activate Agent. Else -> Ignore/Log.
4.  **Action**:
    *   **Agent**: Generate Persona-based response (Naive/Average/Skeptical).
    *   **Extraction**: Regex/LLM extract entities (UPI, Phone, URL) from *incoming* message.
5.  **Storage**: Persist Message, Update Session, Store Entities.
6.  **Response**: Return agent reply to caller (immediate < 300ms where possible, or async logic if allowed, but PRD implies synchronous response flow or fast turn-around). *Note: PRD mandates <300ms response time, suggesting the agent generation might need to be highly optimized or the architecture asynchronous where the API returns "pending" or similar? Wait, PRD says "Agent response generation SHALL complete within 3-5 seconds", but "System SHALL respond to ingress requests within 300ms". This implies the API receiving the message validates it quickly, but the actual 'reply' field in the response needs the agent generation. Given the conflict, we will aim for optimizing agent response or assume the 300ms applies to validation rejection/acceptance overhead, while full generation might take longer but must fit within timeout.* **Correction**: The PRD says "Respond immediately (<300ms)" in component responsibilities but "Agent response... 3-5 seconds" in NFR. The API Response format contains the `reply` field. This implies the caller waits for the agent. We will assume standard synchronous handling but optimized.
7.  **Termination & Callback**: If conditions met (Turns >= 10, Timeout, high confidence intel, or Kill Switch) -> End Session -> Send JSON Callback to GUVI Endpoint.

## 4. Database Schema (PostgreSQL)

### 4.1 Table: `sessions`
| Column | Type | Description |
| :--- | :--- | :--- |
| `session_id` | VARCHAR(255) | Primary Key. Provided by caller or generated. |
| `created_at` | TIMESTAMP | Default `now()` |
| `updated_at` | TIMESTAMP | Update on new message |
| `status` | VARCHAR(50) | `ACTIVE`, `COMPLETED`, `TERMINATED_SAFETY` |
| `risk_score` | FLOAT | 0.0 to 1.0 |
| `agent_engaged` | BOOLEAN | True if agent responded |
| `persona` | VARCHAR(50) | Selected persona for this session |
| `turn_count` | INTEGER | Current turn number |
| `intelligence_confidence` | FLOAT | Max confidence of extracted data |
| `callback_sent` | BOOLEAN | True if callback successfully delivered |

### 4.2 Table: `messages`
| Column | Type | Description |
| :--- | :--- | :--- |
| `id` | SERIAL | Primary Key |
| `session_id` | VARCHAR(255) | FK to `sessions` |
| `turn_number` | INTEGER | Sequence number |
| `sender` | VARCHAR(50) | `scammer` or `user` (agent) |
| `message` | TEXT | Content |
| `timestamp` | TIMESTAMP | Message time |
| `created_at` | TIMESTAMP | Record creation time |

### 4.3 Table: `extracted_entities`
| Column | Type | Description |
| :--- | :--- | :--- |
| `id` | SERIAL | Primary Key |
| `session_id` | VARCHAR(255) | FK to `sessions` |
| `entity_type` | VARCHAR(50) | `upi_id`, `bank_account`, `phone`, `url` |
| `entity_value` | TEXT | The extracted data |
| `confidence` | FLOAT | 0.0 to 1.0 (Filter >= 0.85) |
| `source_turn` | INTEGER | Turn extracted from |
| `metadata` | JSON | Extra info (e.g. provider) |

## 5. API Specification

### 5.1 Ingress: Handle Message
**Endpoint**: `POST /api/v1/honeypot/message`
**Headers**:
*   `x-api-key`: [YOUR_KEY]
*   `Content-Type`: `application/json`

**Request Body** (GUVI Format):
```json
{
  "sessionId": "string",
  "message": {
    "sender": "scammer",
    "text": "Call me at +919876543210 immediately.",
    "timestamp": "ISO-8601 string"
  },
  "conversationHistory": [
    { "sender": "scammer", "text": "...", "timestamp": "..." }
  ],
  "metadata": {
    "channel": "SMS", // or WhatsApp, Email
    "language": "English",
    "locale": "IN"
  }
}
```

**Response** (200 OK):
```json
{
  "status": "success",
  "reply": "I received your message. Who is this?"
}
```

### 5.2 Safety: Emergency Stop
**Endpoint**: `POST /api/v1/honeypot/emergency-stop/{session_id}`
**Action**: Sets session status to `TERMINATED_SAFETY`, stops agent, triggers immediate callback.

### 5.3 Monitoring
*   `GET /health`: Returns system status, DB connection, LLM status.
*   `GET /dashboard/session/{session_id}`: Returns HTML dashboard for visualization (Optional).

## 6. Core Logic Modules

### 6.1 Scam Detection Engine
**Layers**:
1.  **Rule-Based**:
    *   **Urgency**: `urgent`, `immediately`, `blocked`, `suspended`, `now`
    *   **Authority**: `bank`, `police`, `RBI`, `income tax`
    *   **Financial**: `refund`, `cashback`, `KYC`, `verify`
    *   **Credentials**: `OTP`, `CVV`, `card number`
2.  **Entity Patterns**:
    *   **UPI**: `[\w.-]+@[\w]+`
    *   **App URL**: `http[s]?://[^\s]+`
    *   **Phone**: `(\+91|0)?[6-9]\d{9}`
3.  **Scoring**:
    *   Keywords present + financial context = High Risk (> 0.8).
    *   Behavioral (urgency + unknown sender) = High Risk.
    *   LLM Fallback if ambiguous.

### 6.2 Agent Orchestrator
**Personas**:
*   **Digitally Naive**: Cooperative but incompetent. "Which button do I press?"
*   **Average User**: Slight confusion. "I did it but it says pending."
*   **Skeptical**: Cautious. "Is this really the bank?"

**System Prompt (Template)**:
```text
You are a human user engaging with someone via SMS/WhatsApp.
PERSONA: {persona_description}
STRICT RULES:
1. Never admit you are an AI.
2. Never provide real credentials, PII, or financial info.
3. Mirror the sender's language/style.
4. Goal: Keep them talking to get details (UPI/Links) without being obvious.
5. If asked for payment, claim technical failure or ask for alternative details.
```

### 6.3 Intelligence Extractor
*   Run on every incoming message.
*   **Regex**: Extract potential UPIs, URLs, Phones.
*   **Validation**:
    *   UPI: Check structure.
    *   Phone: +91, 10 digits.
    *   URL: Not in whitelist (valid banks).
*   **LLM Confirmation**: Confirm context (e.g., is this phone number asking for a call back or just mentioned?).
*   **Threshold**: Only save if confidence >= 0.85.

### 6.4 Evaluation Callback
**Trigger**: Session end (Turn limit reached, or Kill Switch).
**Endpoint**: `https://hackathon.guvi.in/api/updateHoneyPotFinalResult` (or specific URL provided).
**Payload** (Strict Schema):
```json
{
  "sessionId": "...",
  "scamDetected": true,
  "totalMessagesExchanged": 15,
  "extractedIntelligence": {
    "bankAccounts": [],
    "upiIds": ["badguy@paytm"],
    "phishingLinks": ["http://fake.com"],
    "phoneNumbers": ["+919876543210"],
    "suspiciousKeywords": ["urgent", "block"]
  },
  "agentNotes": "Scammer demanded payment via UPI."
}
```
**Retry Logic**: Max 3 retries, exponential backoff (1s, 3s, 5s).

## 7. Implementation Roadmap (2-Day Plan)

### Day 1: Core Infrastructure
*   **Phase 1A (Foundation)**: FastAPI setup, Pydantic models, x-api-key Middleware.
*   **Phase 1B (Database)**: Postgres setup, SQLAlchemy models, Alembic migrations (optional).
*   **Phase 1C (Detection)**: Implement regex/keyword scanning logic.
*   **Phase 1D (Agent)**: Gemini API integration, Persona management, Prompt engineering.

### Day 2: Intelligence & Integration
*   **Phase 2A (Extraction)**: Regex patterns, extraction logic, entity storage.
*   **Phase 2B (Conversation)**: Session state management, history loading, multi-turn loop.
*   **Phase 2C (Callback)**: Implement correct JSON payload and retry logic.
*   **Phase 2D (Safety)**: Kill switch, PII filtering (redaction), safety flag logging.
*   **Phase 2E (Testing)**: Unit tests for detection/extraction, Integrated API testing.
*   **Phase 2F (Dashboard)**: Simple HTML/Jinja2 view for judging.
*   **Deployment**: Deploy to Railway/Render with `.env` configuration.

## 8. Safety Guidelines
*   **No Attack**: Do not attempt to hack back or spam the scammer.
*   **No Real Data**: Never send real OTPs or bank info.
*   **Audit**: Log all "simulated_action" events (e.g., "pretending to pay").
