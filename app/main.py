"""
Main FastAPI application entry point.
Agentic Honeypot API for Scam Detection & Intelligence Extraction.
"""

from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
import time
import uuid
from datetime import datetime
from typing import Dict, Any

from config.settings import settings
from app.api.routes import health, honeypot, guvi_callback
from app.core.logging import setup_logging, get_logger
from app.core.metrics import setup_metrics, REQUEST_COUNT, REQUEST_DURATION
from app.core.redis import redis_manager
from app.core.session_manager import session_manager
from app.services import callback_manager

# Setup logging
setup_logging()
logger = get_logger(__name__)

# Setup metrics
setup_metrics()

# Create FastAPI application
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Sophisticated scam detection and intelligence extraction system for the GUVI/HCL AI for Impact Hackathon",
    docs_url="/docs" if settings.is_development() else None,
    redoc_url="/redoc" if settings.is_development() else None,
    openapi_url="/openapi.json" if settings.is_development() else None,
)

# Add security middleware
if not settings.is_development() and settings.environment != "test":
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["localhost", "127.0.0.1", "*.railway.app", "*.run.app"]
    )

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://hackathon.guvi.in"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["x-api-key", "content-type"],
)


@app.get("/")
async def root():
    """Root route so base URL returns a helpful message instead of Not Found."""
    return {
        "app": settings.app_name,
        "version": settings.app_version,
        "status": "running",
        "endpoints": {
            "health": "GET /health",
            "honeypot": "POST /api/honeypot (header: x-api-key)",
        },
    }


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Add security headers to all responses."""
    response = await call_next(request)
    
    # Security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    
    # Only setting HSTS for HTTPS or non-development environments
    if request.url.scheme == "https" or not settings.is_development():
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    
    return response


@app.middleware("http")
async def add_request_logging_and_metrics(request: Request, call_next):
    """Add request logging and metrics collection."""
    start_time = time.time()
    correlation_id = str(uuid.uuid4())
    
    # Add correlation ID to request state
    request.state.correlation_id = correlation_id
    
    # Log request start
    logger.info(
        "Request started",
        extra={
            "correlation_id": correlation_id,
            "method": request.method,
            "url": str(request.url),
            "client_ip": request.client.host if request.client else None,
            "user_agent": request.headers.get("user-agent"),
        }
    )
    
    # Process request
    response = await call_next(request)
    
    # Calculate duration
    duration = time.time() - start_time
    
    # Get route template if available to avoid high cardinality
    route = request.scope.get("route")
    endpoint = route.path if route else request.url.path
    
    # Update metrics
    REQUEST_COUNT.labels(
        method=request.method,
        endpoint=endpoint,
        status=response.status_code
    ).inc()
    
    REQUEST_DURATION.labels(
        endpoint=endpoint
    ).observe(duration)
    
    # Log request completion
    logger.info(
        "Request completed",
        extra={
            "correlation_id": correlation_id,
            "method": request.method,
            "url": str(request.url),
            "status_code": response.status_code,
            "duration_ms": round(duration * 1000, 2),
        }
    )
    
    # Add correlation ID to response headers
    response.headers["X-Correlation-ID"] = correlation_id
    
    # Add correlation ID to response headers
    response.headers["X-Correlation-ID"] = correlation_id
    
    return response


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Exception handler for validation errors."""
    return JSONResponse(
        status_code=422,
        content={
            "status": "error",
            "message": "Invalid request schema",
            "details": exc.errors()
        }
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Exception handler for HTTP exceptions."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "status": "error",
            "message": exc.detail
        },
        headers=exc.headers
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler for unhandled errors."""
    correlation_id = getattr(request.state, "correlation_id", str(uuid.uuid4()))
    
    logger.error(
        "Unhandled exception occurred",
        extra={
            "correlation_id": correlation_id,
            "method": request.method,
            "url": str(request.url),
            "exception_type": type(exc).__name__,
            "exception_message": str(exc),
        },
        exc_info=True
    )
    
    response = JSONResponse(
        status_code=500,
        content={
            "status": "error",
            "error": "Internal server error",
            "correlation_id": correlation_id,
            "timestamp": datetime.utcnow().isoformat()
        }
    )
    
    response.headers["X-Correlation-ID"] = correlation_id
    return response


# Include routers
app.include_router(health.router, tags=["Health"])
app.include_router(honeypot.router, prefix="/api", tags=["Honeypot"])
app.include_router(guvi_callback.router, tags=["GUVI Callbacks"])


@app.on_event("startup")
async def startup_event():
    """Application startup event."""
    logger.info(
        "Application starting up",
        extra={
            "app_name": settings.app_name,
            "version": settings.app_version,
            "environment": settings.environment,
            "debug": settings.debug,
        }
    )
    
    # Initialize Redis connection
    try:
        await redis_manager.initialize()
        logger.info("Redis connection initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize Redis connection: {e}")
        # Don't fail startup if Redis is unavailable
    
    # Start session cleanup task
    try:
        await session_manager.start_cleanup_task(interval_minutes=30)
        logger.info("Session cleanup task started")
    except Exception as e:
        logger.error(f"Failed to start session cleanup task: {e}")
    
    # Start callback manager background tasks
    try:
        await callback_manager.start_background_tasks()
        logger.info("Callback manager background tasks started")
    except Exception as e:
        logger.error(f"Failed to start callback manager: {e}")


@app.on_event("shutdown")
async def shutdown_event():
    """Application shutdown event."""
    logger.info("Application shutting down")
    
    # Stop session cleanup task
    try:
        await session_manager.stop_cleanup_task()
        logger.info("Session cleanup task stopped")
    except Exception as e:
        logger.error(f"Error stopping session cleanup task: {e}")
    
    # Stop callback manager background tasks
    try:
        await callback_manager.stop_background_tasks()
        logger.info("Callback manager background tasks stopped")
    except Exception as e:
        logger.error(f"Error stopping callback manager: {e}")
    
    # Close Redis connection
    try:
        await redis_manager.close()
        logger.info("Redis connection closed")
    except Exception as e:
        logger.error(f"Error closing Redis connection: {e}")


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.is_development(),
        workers=settings.workers if settings.is_production() else 1,
        log_level="info",
    )