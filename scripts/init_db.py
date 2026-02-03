#!/usr/bin/env python3
"""
Database initialization script for development.
Creates tables and sets up initial data.
"""

import sys
import os
import logging
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from app.database.connection import create_tables, check_database_health
from config.settings import settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def main():
    """Initialize the database."""
    logger.info("Starting database initialization...")
    
    # Check if database is accessible
    logger.info(f"Connecting to database: {settings.database.url}")
    
    try:
        # Check database health
        if not check_database_health():
            logger.error("Cannot connect to database. Please ensure PostgreSQL is running.")
            return False
        
        logger.info("Database connection successful!")
        
        # Create tables
        logger.info("Creating database tables...")
        create_tables()
        logger.info("Database tables created successfully!")
        
        logger.info("Database initialization completed successfully!")
        return True
        
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)