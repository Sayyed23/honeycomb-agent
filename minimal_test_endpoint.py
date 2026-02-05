#!/usr/bin/env python3
"""
Minimal test endpoint to debug the INVALID_REQUEST_BODY issue.
"""

from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel, Field
from typing import List, Optional, Union
import os

app = FastAPI()

class SimpleMessage(BaseModel):
    sender: str = Field(..., description="Message sender")
    text: str = Field(..., description="Message content")
    timestamp: str = Field(..., description="ISO-8601 timestamp")

class SimpleRequest(BaseModel):
    sessionId: Optional[str] = None
    message: Union[SimpleMessage, str] = Field(..., description="Message content")
    conversationHistory: List[dict] = Field(default_factory=list)

class SimpleResponse(BaseModel):
    status: str = "success"
    reply: str

def verify_api_key(x_api_key: str = Header(...)):
    expected_key = "iR3PgIodG2xKOCsKa7eNK6HrVKMNHOpzQmfDD6wPs"
    if x_api_key != expected_key:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return x_api_key

@app.post("/api/honeypot", response_model=SimpleResponse)
async def test_honeypot(
    request_data: SimpleRequest,
    x_api_key: str = Header(...)
):
    """Minimal test endpoint"""
    # Verify API key
    verify_api_key(x_api_key)
    
    # Extract message text
    if isinstance(request_data.message, str):
        message_text = request_data.message
    else:
        message_text = request_data.message.text
    
    return SimpleResponse(
        status="success",
        reply=f"Received message: {message_text}"
    )

@app.get("/health")
async def health():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)