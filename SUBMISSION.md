# Hackathon submission – what’s done and what you do

## 1. Already set in `.env` (local)

- **x_API_KEY** – Set. Give this **exact value** to the evaluator as the `x-api-key` header.
- **GEMINI_API_KEY** – Set. Agent uses it to generate replies.
- **GUVI_CALLBACK_URL** – Set to `https://hackathon.guvi.in/api/updateHoneyPotFinalResult`. Do not change.

## 2. Expose `POST /api/honeypot` publicly (you do this)

### Option A: Deploy on Railway

1. Push this repo to GitHub and connect the repo to [Railway](https://railway.app).
2. New Project → Deploy from GitHub repo → select this repo.
3. In the service **Variables** tab, add (same as in `.env`):

   | Variable        | Value (from your `.env`) |
   |----------------|---------------------------|
   | `x_API_KEY`    | (copy from .env)          |
   | `GEMINI_API_KEY` | (copy from .env)       |
   | `GUVI_CALLBACK_URL` | `https://hackathon.guvi.in/api/updateHoneyPotFinalResult` |
   | `DATABASE_URL` | For Railway: add Postgres plugin and use the generated `DATABASE_URL`, or keep `sqlite:///./test.db` for a simple deploy |

4. Deploy. Railway will assign a URL like `https://your-app.up.railway.app`.
5. Your **public honeypot endpoint** is:
   ```text
   POST https://your-app.up.railway.app/api/honeypot
   ```

### Option B: Other hosts (Render, Fly.io, etc.)

- Run the app with `uvicorn app.main:app --host 0.0.0.0 --port $PORT` (or use the Dockerfile).
- Set the same variables as above in the host’s environment.
- Your public endpoint will be `https://<your-host-domain>/api/honeypot`.

## 3. What to give the evaluator

Submit these in the hackathon portal / form:

| What to submit | Value |
|----------------|--------|
| **API base URL** | `https://your-app.up.railway.app` (or your deployed URL) |
| **Honeypot endpoint** | `POST https://your-app.up.railway.app/api/honeypot` |
| **x-api-key** (header) | The exact value of `x_API_KEY` from your `.env` (e.g. `iR3PgIodG2xKOCsKa7eNK6HrVKMNHOpzQmfDD6wPs`) |

Evaluator will call:

- **URL:** `https://<your-url>/api/honeypot`
- **Method:** POST  
- **Headers:** `x-api-key: <your x_API_KEY>`, `Content-Type: application/json`  
- **Body:** As in problem statement (§6.1 / §6.2).

## 4. Quick checklist

- [ ] `.env` has `x_API_KEY`, `GEMINI_API_KEY`, `GUVI_CALLBACK_URL` (already done).
- [ ] App is deployed and the public URL is reachable.
- [ ] Same env vars are set in the deployment (Railway/host).
- [ ] Evaluator has: public URL and the **same** `x_API_KEY` value for the `x-api-key` header.
