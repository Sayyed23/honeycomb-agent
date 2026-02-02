# Agentic Honeypot (SentinelHP) - Task List

## Day 1: Core Infrastructure

- [x] **Phase 1A: Project Foundation**
    - [x] Create project structure (folders, files)
    - [x] Setup `requirements.txt` and install dependencies
    - [x] Implement `app/core/config.py` (Settings, env vars)
    - [x] Implement `app/main.py` (FastAPI app skeleton, CORS, Middleware)
    - [x] Implement `x-api-key` security middleware
    - [x] Define Pydantic schemas (`app/schemas.py`) matching GUVI spec

- [x] **Phase 1B: Database Setup**
    - [x] Define SQLAlchemy Base
    - [x] Implement Models: `Session`, `Message`, `ExtractedEntity` (`app/db/models.py`)
    - [x] Setup Database connection/session dependency (`app/db/session.py`)

- [x] **Phase 1C: Scam Detection Layer**
    - [x] Implement `ScamDetector` class (`app/services/detection.py`)
    - [x] Add Keyword-based detection logic
    - [x] Add Regex Pattern detection logic
    - [x] Implement Risk Scoring logic

- [x] **Phase 1D: Agent & Agent Integration (Initial)**
    - [x] Setup Google Gemini wrapper (`app/services/llm.py`)
    - [x] Define Prompt Templates
    - [x] Create simple Agent interface

## Day 2: Intelligence & Integration

- [x] **Phase 2A: Extraction Pipeline**
    - [x] Implement Intelligence Extractor (`app/services/extraction.py`)
    - [x] Integrate with LLM for confirmation
    - [x] Entity storage logic

- [x] **Phase 2B: Conversation Management**
    - [x] Implement `api/v1/honeypot.py` endpoints
    - [x] Session create/update logic
    - [x] Multi-turn state handling

- [x] **Phase 2C: Callback & Safety**
    - [x] Implement `EvaluationCallback` (`app/services/callback.py`)
    - [x] Implement Safety/Ethical Guardrails (`app/services/safety.py`)
    - [x] Kill Switch Endpoint

- [x] **Phase 2F: Dashboard (Optional)**
    - [x] Simple HTML Dashboard

- [x] **Phase 2E: Testing & Deployment**
    - [x] Unit Tests
    - [x] Integration Tests
    - [x] Dockerfile / Railway Setup
