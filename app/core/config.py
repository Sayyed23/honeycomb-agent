import os
from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    PROJECT_NAME: str = "Agentic Honeypot API"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    
    # Security
    API_KEY: str = "test-secret-key" # Change in production
    
    # Database
    DATABASE_URL: str = "sqlite:///./honeypot.db" # Default to SQLite for easy local dev, PostgreSQL for prod
    
    # LLM
    GOOGLE_API_KEY: Optional[str] = None
    
    # Integration
    EVALUATION_ENDPOINT: str = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
    
    LOG_LEVEL: str = "INFO"

    class Config:
        env_file = ".env"
        case_sensitive = True
        extra = "ignore" # Allow extra env vars

settings = Settings()
