#!/bin/sh
set -e

# Use PORT environment variable or default to 8000
PORT=${PORT:-8000}

# Force SQLite usage for Railway deployment
export DATABASE_URL="sqlite:///./test.db"

echo "Starting server on port $PORT"
echo "Using database: $DATABASE_URL"

# Start the application
exec uvicorn app.main:app --host 0.0.0.0 --port "$PORT"