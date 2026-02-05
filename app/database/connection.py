"""
Database connection management and session handling.
"""

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session as SQLAlchemySession
from sqlalchemy.pool import QueuePool
from typing import Generator
import logging

from config.settings import settings

logger = logging.getLogger(__name__)

# Create database engine with connection pooling
if settings.database.url.startswith("sqlite"):
    # SQLite configuration for testing
    engine = create_engine(
        settings.database.url,
        echo=settings.database.echo,
        connect_args={"check_same_thread": False}
    )
else:
    # PostgreSQL configuration for production
    engine = create_engine(
        settings.database.url,
        echo=settings.database.echo,
        poolclass=QueuePool,
        pool_size=settings.database.pool_size,
        max_overflow=settings.database.max_overflow,
        pool_timeout=settings.database.pool_timeout,
        pool_recycle=settings.database.pool_recycle,
        # Additional PostgreSQL-specific settings
        pool_pre_ping=True,  # Validate connections before use
        connect_args={
            "options": "-c timezone=utc",  # Set timezone to UTC
            "application_name": "honeypot_api",  # Application name for monitoring
        }
    )

# Create session factory
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    expire_on_commit=False  # Keep objects accessible after commit
)


def get_db() -> Generator[SQLAlchemySession, None, None]:
    """
    Dependency function to get database session.
    
    Yields:
        SQLAlchemySession: Database session instance
        
    Usage:
        @app.get("/endpoint")
        async def endpoint(db: Session = Depends(get_db)):
            # Use db session here
            pass
    """
    db = SessionLocal()
    try:
        yield db
    except Exception as e:
        logger.error(f"Database session error: {e}")
        db.rollback()
        raise
    finally:
        db.close()


def check_database_health() -> bool:
    """
    Check database connectivity and health.
    
    Returns:
        bool: True if database is healthy, False otherwise
    """
    try:
        db = SessionLocal()
        # Simple query to test connection
        db.execute(text("SELECT 1"))
        db.close()
        return True
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return False


def create_tables():
    """
    Create all database tables.
    This should only be used in development or testing.
    In production, use Alembic migrations.
    """
    from .models import Base
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables created successfully")


def drop_tables():
    """
    Drop all database tables.
    WARNING: This will delete all data!
    Only use in development or testing.
    """
    from .models import Base
    Base.metadata.drop_all(bind=engine)
    logger.warning("All database tables dropped")