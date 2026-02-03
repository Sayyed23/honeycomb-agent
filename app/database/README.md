# Database Configuration

This directory contains the database configuration for the Agentic Honeypot API.

## Structure

- `__init__.py` - Package initialization and exports
- `connection.py` - Database connection management and session handling
- `models.py` - SQLAlchemy models for all database tables
- `utils.py` - Database utility functions and the DatabaseManager class

## Models

### Session
Tracks conversation sessions with risk scores, persona types, and timing information.

### Message
Stores individual messages in conversations with role, content, and language information.

### ExtractedEntity
Contains entities extracted from conversations (UPI IDs, phone numbers, URLs, etc.).

### RiskAssessment
Stores risk analysis results for messages with confidence scores and detection methods.

### GUVICallback
Tracks callback attempts to the GUVI evaluation system.

## Usage

### Basic Database Operations

```python
from app.database import get_db, DatabaseManager

# Get database session (for FastAPI dependency injection)
def some_endpoint(db: Session = Depends(get_db)):
    # Use db session here
    pass

# Use DatabaseManager for common operations
db = SessionLocal()
manager = DatabaseManager(db)

# Create a session
session = manager.create_session(
    session_id="test-123",
    risk_score=0.85,
    confidence_level=0.90,
    persona_type="digitally_naive"
)

# Add a message
message = manager.add_message(
    session_id="test-123",
    role="user",
    content="Hello, I need help",
    language="en"
)

# Complete the session
manager.complete_session("test-123", engagement_duration=120)
```

### Database Initialization

For development, you can initialize the database using:

```bash
python scripts/init_db.py
```

### Migrations

Use Alembic for database migrations:

```bash
# Generate a new migration
alembic revision --autogenerate -m "Description of changes"

# Apply migrations
alembic upgrade head

# View migration SQL without applying
alembic upgrade --sql head
```

## Configuration

Database settings are configured in `config/settings.py`:

- `DATABASE_URL` - PostgreSQL connection string
- `DATABASE_ECHO` - Enable SQLAlchemy query logging
- `DATABASE_POOL_SIZE` - Connection pool size
- `DATABASE_MAX_OVERFLOW` - Maximum overflow connections
- `DATABASE_POOL_TIMEOUT` - Connection timeout
- `DATABASE_POOL_RECYCLE` - Connection recycle time

## Requirements

The database configuration requires:
- PostgreSQL 12+
- SQLAlchemy 2.0+
- Alembic for migrations
- psycopg2-binary for PostgreSQL connectivity