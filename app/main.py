from fastapi import FastAPI, Depends, HTTPException, Header, status, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from app.core.config import settings
from app.db import models
from app.db.session import engine, get_db
from app.schemas import HoneypotRequest, HoneypotResponse

# Create Database Tables (Simple auto-migration for dev)
models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Agentic Honeypot API for Scam Detection"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API Key Middleware / Dependency
async def verify_api_key(x_api_key: str = Header(...)):
    if x_api_key != settings.API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API Key",
        )
    return x_api_key

from app.api.v1 import honeypot, dashboard

app.include_router(honeypot.router, prefix="/api/v1/honeypot", tags=["Honeypot"])
app.include_router(dashboard.router, prefix="/dashboard", tags=["Dashboard"])

# Root/Health
@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "version": settings.VERSION,
        "database": "connected"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
