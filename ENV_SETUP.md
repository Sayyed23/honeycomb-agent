# Environment setup – where to get each value

Copy `.env.example` to `.env`, then set the variables below. **Required** = must be set for submission.

---

## Required for submission

| Variable | Where to get it |
|--------|------------------|
| **x_API_KEY** | **You choose it.** Any secret string (e.g. generate with `openssl rand -hex 24`). The evaluator will call your API with header `x-api-key: <this value>`, so you must give them this same key (via hackathon dashboard / instructions). |

---

## Required for AI replies (agent responses)

| Variable | Where to get it |
|--------|------------------|
| **GEMINI_API_KEY** | **Google AI Studio:** https://aistudio.google.com/app/apikey — Create a project, then “Create API key”. Free tier is enough for testing. |

---

## Optional / already set

| Variable | Where to get it |
|--------|------------------|
| **DATABASE_URL** | **Local:** keep `sqlite:///./test.db`. **Production:** from your host (e.g. Railway → “Variables” → add `DATABASE_URL` from “Postgres” plugin; or Render/Neon “Connection string”). |
| **GUVI_CALLBACK_URL** | Leave as `https://hackathon.guvi.in/api/updateHoneyPotFinalResult` (hackathon endpoint). |
| **GUVI_API_KEY** | **From the hackathon:** GUVI / hackathon dashboard, participant guide, or email (e.g. hackathon.guvi.in). Only set if the callback endpoint is documented as requiring auth; otherwise keep `test-guvi-key`. |
| **API_KEY_SECRET** | **You generate it** – not from any website. Used only inside your app for hashing; never sent to GUVI or evaluator. Use any random string (e.g. `python -c "import secrets; print(secrets.token_hex(24))"` or PowerShell one-liner). For production, pick a new random value. |
| **REDIS_*** | Optional. App works without Redis. If you add Redis (e.g. Railway Redis), set `REDIS_URL` from the provider. |
| **ENVIRONMENT** | `development` locally, `production` on Railway/Render etc. |
| **PORT** | Set by host (e.g. Railway sets `PORT`). Local default 8000. |

---

## Quick checklist

1. Copy: `cp .env.example .env` (or copy the file and rename to `.env`).
2. Set **x_API_KEY** to your chosen secret and share that value with the evaluator (per hackathon instructions).
3. Set **GEMINI_API_KEY** from https://aistudio.google.com/app/apikey so the agent can generate replies.
4. For production: set **DATABASE_URL** if you use Postgres; leave **DATABASE_URL** as SQLite for local runs.
5. Leave **GUVI_CALLBACK_URL** as in `.env.example` unless the hackathon specifies a different URL.

After that, start the app and call `POST /api/honeypot` with header `x-api-key: <your x_API_KEY>`.
