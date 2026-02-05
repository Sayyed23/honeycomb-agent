# Problem Statement 2 – Compliance Checklist

Verification that the Agentic Honey-Pot implementation matches the GUVI hackathon requirements.

---

## 1. REST API – What You Need to Build

| Requirement | Status | Implementation |
|-------------|--------|----------------|
| Deploy a public REST API | ✅ | FastAPI app; deploy to Railway/Render etc. |
| Accepts incoming message events | ✅ | `POST /api/honeypot` accepts request body |
| Detects scam intent | ✅ | `ScamDetectionEngine.calculate_risk_score()` |
| Hands control to an AI Agent | ✅ | `agent_activation_engine.should_activate_agent()` → ACTIVATE |
| Engages scammers autonomously | ✅ | `conversation_engine.generate_reply()` with persona |
| Extracts actionable intelligence | ✅ | `entity_extraction_engine.extract_entities_sync()` → UPI, phone, URL, bank, etc. |
| Returns structured JSON response | ✅ | `{"status": "success", "reply": "..."}` |
| Secures access using an API key | ✅ | Header `x-api-key` validated in `verify_api_key()` |

---

## 2. API Authentication

| Requirement | Status | Implementation |
|-------------|--------|----------------|
| `x-api-key: YOUR_SECRET_API_KEY` | ✅ | `Header(..., alias can be x-api-key)`; env `x_API_KEY` |
| `Content-Type: application/json` | ✅ | Client sends JSON; FastAPI parses JSON body |

---

## 3. API Request Format (Input)

| Field | Required | Status | Implementation |
|-------|----------|--------|----------------|
| `sessionId` | Yes | ✅ | `HoneypotRequest.sessionId` or `session_id` |
| `message` | Yes | ✅ | Object or string; object has `sender`, `text`, `timestamp` |
| `message.sender` | Yes | ✅ | `"scammer"` or `"user"` |
| `message.text` | Yes | ✅ | Message content |
| `message.timestamp` | Yes | ✅ | Epoch ms (int) or string – `Union[int, str]` |
| `conversationHistory` | Optional (required for follow-ups) | ✅ | List of `{sender, text, timestamp}`; default `[]` |
| `metadata` | Optional | ✅ | `channel`, `language`, `locale` |

First-message and follow-up examples from the problem statement are both supported.

---

## 4. Agent Output (Response)

| Requirement | Status | Implementation |
|-------------|--------|----------------|
| `{"status": "success", "reply": "..."}` | ✅ | `HoneypotResponse(status="success", reply=ai_reply)` |

---

## 5. Mandatory Final Result Callback

| Requirement | Status | Implementation |
|-------------|--------|----------------|
| Endpoint | ✅ | `POST https://hackathon.guvi.in/api/updateHoneyPotFinalResult` (from `GUVI_CALLBACK_URL`) |
| Content-Type: application/json | ✅ | Set in `guvi_callback.py` headers |
| Payload: `sessionId` | ✅ | `build_guvi_final_result_payload()` |
| Payload: `scamDetected` | ✅ | Derived from risk ≥ 0.6 |
| Payload: `totalMessagesExchanged` | ✅ | `session.total_turns` |
| Payload: `extractedIntelligence.bankAccounts` | ✅ | From DB `ExtractedEntity` type `bank_account` |
| Payload: `extractedIntelligence.upiIds` | ✅ | From DB type `upi_id` |
| Payload: `extractedIntelligence.phishingLinks` | ✅ | From DB type `url` |
| Payload: `extractedIntelligence.phoneNumbers` | ✅ | From DB type `phone_number` |
| Payload: `extractedIntelligence.suspiciousKeywords` | ✅ | From risk_factors + defaults |
| Payload: `agentNotes` | ✅ | Summary string (risk, persona, turns) |
| Sent when scam detected + engagement done | ✅ | Triggered when `ACTIVATE` and risk ≥ 0.6; after `record_interaction` (so at least one exchange stored) |
| timeout=5 | ✅ | `timeout=5.0` in `http_client.post()` |

---

## 6. Agent Behavior

| Expectation | Status | Implementation |
|-------------|--------|----------------|
| Handle multi-turn conversations | ✅ | `conversationHistory` passed to detection and `generate_reply()` |
| Adapt responses dynamically | ✅ | LLM/persona-based replies via conversation engine |
| Avoid revealing scam detection | ✅ | Persona-driven, human-like replies |
| Behave like a real human | ✅ | Persona types (e.g. digitally_naive, skeptical) |
| Self-correction if needed | ✅ | Handled in conversation/LLM logic |

---

## 7. Evaluation Flow

| Step | Status |
|------|--------|
| Platform sends suspected scam message | ✅ API accepts it |
| System analyzes the message | ✅ Scam detection + risk score |
| If scam intent detected, AI Agent is activated | ✅ Activation decision → ACTIVATE |
| Agent continues the conversation | ✅ Reply generated and returned |
| Intelligence is extracted and returned | ✅ Entities stored; callback payload includes `extractedIntelligence` |
| Performance is evaluated | ✅ Callback sent to GUVI endpoint |

---

## 8. Constraints & Ethics

| Rule | Status |
|------|--------|
| No impersonation of real individuals | ✅ Personas are generic (e.g. “digitally_naive”) |
| No illegal instructions | ✅ Agent only engages and extracts; no harmful actions |
| No harassment | ✅ Deflection / non-engagement when not activated |
| Responsible data handling | ✅ Data in DB; callback payload as per spec only |

---

## 9. Configuration

| Item | Where |
|------|--------|
| API key (for `x-api-key` header) | `.env` → `x_API_KEY`; give same value to evaluator |
| GUVI callback URL | `.env` → `GUVI_CALLBACK_URL` (default set in `config.settings`) |
| Gemini (AI replies) | `.env` → `GEMINI_API_KEY` |

---

## 10. Public Endpoints Summary

- **Honeypot (evaluator calls this)**  
  - `POST /api/honeypot`  
  - Headers: `x-api-key: <your x_API_KEY>`, `Content-Type: application/json`  
  - Body: as in problem statement (§6.1 / §6.2)  
  - Response: `{"status": "success", "reply": "..."}`  

- **Callback (we call GUVI)**  
  - `POST https://hackathon.guvi.in/api/updateHoneyPotFinalResult`  
  - Body: `sessionId`, `scamDetected`, `totalMessagesExchanged`, `extractedIntelligence`, `agentNotes`  

---

**Conclusion:** The implementation is aligned with Problem Statement 2. Ensure `.env` has `x_API_KEY` and `GEMINI_API_KEY` set, and that the evaluator has your API base URL and the same `x_API_KEY` value for the `x-api-key` header.
