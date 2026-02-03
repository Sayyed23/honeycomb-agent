"""
Prometheus metrics configuration and collection.
"""

from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST
from fastapi import Response
from typing import Dict, Any

from config.settings import settings

# Define application metrics
REQUEST_COUNT = Counter(
    'http_requests_total',
    'Total HTTP requests',
    ['method', 'endpoint', 'status']
)

REQUEST_DURATION = Histogram(
    'http_request_duration_seconds',
    'HTTP request duration in seconds',
    ['endpoint']
)

ACTIVE_SESSIONS = Gauge(
    'active_sessions_total',
    'Number of active conversation sessions'
)

SCAM_DETECTION_ACCURACY = Gauge(
    'scam_detection_accuracy',
    'Current scam detection accuracy'
)

SCAM_DETECTION_COUNT = Counter(
    'scam_detection_total',
    'Total scam detection attempts',
    ['result', 'confidence_level']
)

AGENT_ACTIVATION_COUNT = Counter(
    'agent_activation_total',
    'Total agent activations',
    ['persona', 'activation_reason']
)

LLM_API_CALLS = Counter(
    'llm_api_calls_total',
    'Total LLM API calls',
    ['model', 'status']
)

LLM_API_DURATION = Histogram(
    'llm_api_duration_seconds',
    'LLM API call duration in seconds',
    ['model']
)

ENTITY_EXTRACTION_COUNT = Counter(
    'entity_extraction_total',
    'Total entity extractions',
    ['entity_type', 'confidence_level']
)

GUVI_CALLBACK_COUNT = Counter(
    'guvi_callback_total',
    'Total GUVI callbacks',
    ['status']
)

GUVI_CALLBACK_DURATION = Histogram(
    'guvi_callback_duration_seconds',
    'GUVI callback duration in seconds'
)

DATABASE_OPERATIONS = Counter(
    'database_operations_total',
    'Total database operations',
    ['operation', 'table', 'status']
)

DATABASE_CONNECTION_POOL = Gauge(
    'database_connection_pool_size',
    'Current database connection pool size'
)

REDIS_OPERATIONS = Counter(
    'redis_operations_total',
    'Total Redis operations',
    ['operation', 'status']
)

SYSTEM_HEALTH = Gauge(
    'system_health_status',
    'System health status (1=healthy, 0=unhealthy)',
    ['component']
)


def setup_metrics() -> None:
    """Initialize metrics collection."""
    # Initialize system health metrics
    SYSTEM_HEALTH.labels(component='database').set(0)
    SYSTEM_HEALTH.labels(component='redis').set(0)
    SYSTEM_HEALTH.labels(component='llm').set(0)
    SYSTEM_HEALTH.labels(component='overall').set(0)


def get_metrics_response() -> Response:
    """Generate Prometheus metrics response."""
    metrics_data = generate_latest()
    return Response(
        content=metrics_data,
        media_type=CONTENT_TYPE_LATEST
    )


class MetricsCollector:
    """Helper class for collecting application metrics."""
    
    @staticmethod
    def record_scam_detection(result: str, confidence: float, risk_score: float):
        """Record scam detection metrics."""
        confidence_level = "high" if confidence >= 0.8 else "medium" if confidence >= 0.6 else "low"
        SCAM_DETECTION_COUNT.labels(result=result, confidence_level=confidence_level).inc()
        
        # Update accuracy gauge (this would be calculated from recent results in practice)
        if result == "scam_detected":
            SCAM_DETECTION_ACCURACY.set(min(confidence, 1.0))
    
    @staticmethod
    def record_agent_activation(persona: str, reason: str):
        """Record agent activation metrics."""
        AGENT_ACTIVATION_COUNT.labels(persona=persona, activation_reason=reason).inc()
    
    @staticmethod
    def record_llm_call(model: str, status: str, duration: float):
        """Record LLM API call metrics."""
        LLM_API_CALLS.labels(model=model, status=status).inc()
        LLM_API_DURATION.labels(model=model).observe(duration)
    
    @staticmethod
    def record_entity_extraction(entity_type: str, confidence: float):
        """Record entity extraction metrics."""
        confidence_level = "high" if confidence >= 0.8 else "medium" if confidence >= 0.6 else "low"
        ENTITY_EXTRACTION_COUNT.labels(entity_type=entity_type, confidence_level=confidence_level).inc()
    
    @staticmethod
    def record_guvi_callback(status: str, duration: float):
        """Record GUVI callback metrics."""
        GUVI_CALLBACK_COUNT.labels(status=status).inc()
        GUVI_CALLBACK_DURATION.observe(duration)
    
    @staticmethod
    def record_database_operation(operation: str, table: str, status: str):
        """Record database operation metrics."""
        DATABASE_OPERATIONS.labels(operation=operation, table=table, status=status).inc()
    
    @staticmethod
    def record_redis_operation(operation: str, status: str):
        """Record Redis operation metrics."""
        REDIS_OPERATIONS.labels(operation=operation, status=status).inc()
    
    @staticmethod
    def update_active_sessions(count: int):
        """Update active sessions count."""
        ACTIVE_SESSIONS.set(count)
    
    @staticmethod
    def update_system_health(component: str, is_healthy: bool):
        """Update system health status."""
        SYSTEM_HEALTH.labels(component=component).set(1 if is_healthy else 0)
    
    @staticmethod
    def update_database_pool_size(size: int):
        """Update database connection pool size."""
        DATABASE_CONNECTION_POOL.set(size)