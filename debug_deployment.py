#!/usr/bin/env python3
"""
Debug script to help diagnose deployment issues.
"""

import os
import sys
import asyncio
import logging
from datetime import datetime

# Add the app directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Setup basic logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)


def check_environment():
    """Check environment variables and configuration."""
    logger.info("=== Environment Check ===")
    
    # Check critical environment variables
    critical_vars = [
        'PORT', 'ENVIRONMENT', 'GEMINI_API_KEY', 'x_API_KEY'
    ]
    
    for var in critical_vars:
        value = os.getenv(var)
        if value:
            # Mask sensitive values
            if 'key' in var.lower() or 'secret' in var.lower():
                masked_value = value[:4] + '*' * (len(value) - 8) + value[-4:] if len(value) > 8 else '*' * len(value)
                logger.info(f"{var}: {masked_value}")
            else:
                logger.info(f"{var}: {value}")
        else:
            logger.warning(f"{var}: NOT SET")
    
    # Check optional variables
    optional_vars = ['DATABASE_URL', 'REDIS_URL']
    for var in optional_vars:
        value = os.getenv(var)
        if value:
            logger.info(f"{var}: {value[:20]}...")
        else:
            logger.info(f"{var}: Using default")


def check_imports():
    """Check if all required modules can be imported."""
    logger.info("=== Import Check ===")
    
    try:
        from config.settings import settings
        logger.info("✅ Settings imported successfully")
        logger.info(f"App: {settings.app_name} v{settings.app_version}")
        logger.info(f"Environment: {settings.environment}")
        logger.info(f"Host: {settings.host}:{settings.port}")
    except Exception as e:
        logger.error(f"❌ Settings import failed: {e}")
        return False
    
    try:
        from app.main import app
        logger.info("✅ FastAPI app imported successfully")
    except Exception as e:
        logger.error(f"❌ FastAPI app import failed: {e}")
        return False
    
    try:
        from app.core.redis import redis_manager
        logger.info("✅ Redis manager imported successfully")
    except Exception as e:
        logger.error(f"❌ Redis manager import failed: {e}")
        return False
    
    try:
        from app.core.session_manager import session_manager
        logger.info("✅ Session manager imported successfully")
    except Exception as e:
        logger.error(f"❌ Session manager import failed: {e}")
        return False
    
    try:
        from app.services.callback_manager import callback_manager
        logger.info("✅ Callback manager imported successfully")
    except Exception as e:
        logger.error(f"❌ Callback manager import failed: {e}")
        return False
    
    return True


async def test_startup_components():
    """Test individual startup components."""
    logger.info("=== Component Startup Test ===")
    
    try:
        from app.core.redis import redis_manager
        logger.info("Testing Redis connection...")
        await asyncio.wait_for(redis_manager.initialize(), timeout=5.0)
        logger.info("✅ Redis connection successful")
    except asyncio.TimeoutError:
        logger.warning("⚠️ Redis connection timed out (non-fatal)")
    except Exception as e:
        logger.warning(f"⚠️ Redis connection failed: {e} (non-fatal)")
    
    try:
        from app.core.session_manager import session_manager
        logger.info("Testing session manager...")
        await asyncio.wait_for(session_manager.start_cleanup_task(interval_minutes=30), timeout=3.0)
        logger.info("✅ Session manager started successfully")
        await session_manager.stop_cleanup_task()
    except asyncio.TimeoutError:
        logger.warning("⚠️ Session manager startup timed out (non-fatal)")
    except Exception as e:
        logger.warning(f"⚠️ Session manager failed: {e} (non-fatal)")
    
    try:
        from app.services.callback_manager import callback_manager
        logger.info("Testing callback manager...")
        await asyncio.wait_for(callback_manager.start_background_tasks(), timeout=3.0)
        logger.info("✅ Callback manager started successfully")
        await callback_manager.stop_background_tasks()
    except asyncio.TimeoutError:
        logger.warning("⚠️ Callback manager startup timed out (non-fatal)")
    except Exception as e:
        logger.warning(f"⚠️ Callback manager failed: {e} (non-fatal)")


def check_database():
    """Check database connectivity."""
    logger.info("=== Database Check ===")
    
    try:
        from app.database.connection import check_database_health
        if check_database_health():
            logger.info("✅ Database connection healthy")
        else:
            logger.warning("⚠️ Database connection failed")
    except Exception as e:
        logger.error(f"❌ Database check failed: {e}")


async def main():
    """Main diagnostic function."""
    logger.info(f"=== Deployment Debug Started at {datetime.utcnow()} ===")
    
    # Check environment
    check_environment()
    
    # Check imports
    if not check_imports():
        logger.error("Import check failed - cannot continue")
        return
    
    # Check database
    check_database()
    
    # Test startup components
    await test_startup_components()
    
    logger.info("=== Deployment Debug Completed ===")
    logger.info("If all checks passed, the application should start successfully")


if __name__ == "__main__":
    asyncio.run(main())