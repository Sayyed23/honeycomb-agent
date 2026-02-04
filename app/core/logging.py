"""
Structured logging configuration for the application.
"""

import logging
import json
import sys
from datetime import datetime
from typing import Dict, Any, Optional

from config.settings import settings


class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging."""
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        
        # Add extra fields if present
        if hasattr(record, "correlation_id"):
            log_entry["correlation_id"] = record.correlation_id
        
        if hasattr(record, "session_id"):
            log_entry["session_id"] = record.session_id
        
        if hasattr(record, "risk_score"):
            log_entry["risk_score"] = record.risk_score
        
        if hasattr(record, "user_id"):
            log_entry["user_id"] = record.user_id
        
        # Add exception info if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        
        # Add any additional extra fields
        for key, value in record.__dict__.items():
            if key not in {
                "name", "msg", "args", "levelname", "levelno", "pathname",
                "filename", "module", "lineno", "funcName", "created",
                "msecs", "relativeCreated", "thread", "threadName",
                "processName", "process", "getMessage", "exc_info",
                "exc_text", "stack_info", "correlation_id", "session_id",
                "risk_score", "user_id"
            } and not key.startswith("_"):
                log_entry[key] = value
        
        return json.dumps(log_entry, default=str, ensure_ascii=False)


def setup_logging() -> None:
    """Setup application logging configuration."""
    # Remove existing handlers
    root_logger = logging.getLogger()
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(JSONFormatter())
    
    # Configure root logger
    root_logger.addHandler(console_handler)
    root_logger.setLevel(logging.INFO)  # Default to INFO level
    
    # Configure specific loggers
    logging.getLogger("uvicorn.access").disabled = True  # Disable uvicorn access logs
    logging.getLogger("uvicorn.error").setLevel(logging.WARNING)
    
    # Set third-party library log levels
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
    logging.getLogger("redis").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance with the specified name."""
    return logging.getLogger(name)


class ContextLogger:
    """Logger wrapper that maintains context across log calls."""
    
    def __init__(self, logger: logging.Logger, context: Optional[Dict[str, Any]] = None):
        self.logger = logger
        self.context = context or {}
    
    def _log(self, level: int, message: str, **kwargs):
        """Log message with context."""
        # Extract standard logging arguments
        exc_info = kwargs.pop('exc_info', None)
        stack_info = kwargs.pop('stack_info', None)
        stacklevel = kwargs.pop('stacklevel', 1)
        
        # Everything else goes into extra
        extra = {**self.context, **kwargs}
        
        self.logger.log(
            level, 
            message, 
            exc_info=exc_info, 
            stack_info=stack_info, 
            stacklevel=stacklevel, 
            extra=extra
        )
    
    def debug(self, message: str, **kwargs):
        """Log debug message."""
        self._log(logging.DEBUG, message, **kwargs)
    
    def info(self, message: str, **kwargs):
        """Log info message."""
        self._log(logging.INFO, message, **kwargs)
    
    def warning(self, message: str, **kwargs):
        """Log warning message."""
        self._log(logging.WARNING, message, **kwargs)
    
    def error(self, message: str, **kwargs):
        """Log error message."""
        self._log(logging.ERROR, message, **kwargs)
    
    def critical(self, message: str, **kwargs):
        """Log critical message."""
        self._log(logging.CRITICAL, message, **kwargs)
    
    def with_context(self, **context) -> "ContextLogger":
        """Create new logger with additional context."""
        new_context = {**self.context, **context}
        return ContextLogger(self.logger, new_context)