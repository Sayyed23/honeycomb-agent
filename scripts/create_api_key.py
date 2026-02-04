#!/usr/bin/env python3
"""
Script to create API keys for the Agentic Honeypot API.
"""

import asyncio
import sys
import argparse
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

# Add the project root to the Python path
sys.path.insert(0, '.')

from app.database.connection import get_db
from app.core.auth import APIKeyManager
from config.settings import settings


async def create_api_key(
    key_name: str,
    description: Optional[str] = None,
    rate_limit_per_hour: int = 1000,
    permissions: Optional[Dict[str, Any]] = None,
    created_by: Optional[str] = None,
    expires_days: Optional[int] = None
) -> None:
    """
    Create a new API key.
    
    Args:
        key_name: Human-readable name for the key
        description: Optional description
        rate_limit_per_hour: Rate limit for this key
        permissions: Optional permissions object
        created_by: Who created this key
        expires_days: Optional expiration in days from now
    """
    # Calculate expiration date if specified
    expires_at = None
    if expires_days:
        expires_at = datetime.utcnow() + timedelta(days=expires_days)
    
    # Get database session
    from app.database.connection import SessionLocal
    db = SessionLocal()
    try:
        try:
            # Create the API key
            api_key, db_key = await APIKeyManager.create_api_key(
                db=db,
                key_name=key_name,
                description=description,
                rate_limit_per_hour=rate_limit_per_hour,
                permissions=permissions,
                created_by=created_by,
                expires_at=expires_at
            )
            
            print(f"✅ API Key created successfully!")
            print(f"   Name: {db_key.key_name}")
            print(f"   Key: {api_key}")
            print(f"   Prefix: {db_key.key_prefix}")
            print(f"   Rate Limit: {db_key.rate_limit_per_hour} requests/hour")
            if db_key.expires_at:
                print(f"   Expires: {db_key.expires_at}")
            print(f"   Created: {db_key.created_at}")
            print()
            print("⚠️  IMPORTANT: Save this API key securely. It cannot be retrieved again!")
            print(f"   Use it in requests with the header: x-api-key: {api_key}")
            
        except Exception as e:
            print(f"❌ Error creating API key: {e}")
            sys.exit(1)
    finally:
        db.close()


async def list_api_keys() -> None:
    """List all existing API keys."""
    from app.database.models import APIKey
    
    async for db in get_db():
        try:
            keys = db.query(APIKey).all()
            
            if not keys:
                print("No API keys found.")
                return
            
            print(f"Found {len(keys)} API key(s):")
            print()
            
            for key in keys:
                status = "🟢 Active" if key.is_active else "🔴 Inactive"
                expired = ""
                if key.expires_at and key.expires_at < datetime.utcnow():
                    expired = " (EXPIRED)"
                
                print(f"  {status}{expired}")
                print(f"    Name: {key.key_name}")
                print(f"    Prefix: {key.key_prefix}...")
                print(f"    Rate Limit: {key.rate_limit_per_hour}/hour")
                print(f"    Usage: {key.usage_count} total requests")
                print(f"    Last Used: {key.last_used or 'Never'}")
                print(f"    Created: {key.created_at}")
                if key.expires_at:
                    print(f"    Expires: {key.expires_at}")
                if key.description:
                    print(f"    Description: {key.description}")
                print()
            
            break
            
        except Exception as e:
            print(f"❌ Error listing API keys: {e}")
            sys.exit(1)


async def deactivate_api_key(key_prefix: str) -> None:
    """Deactivate an API key by prefix."""
    from app.database.models import APIKey
    
    async for db in get_db():
        try:
            key = db.query(APIKey).filter(APIKey.key_prefix == key_prefix).first()
            
            if not key:
                print(f"❌ API key with prefix '{key_prefix}' not found.")
                sys.exit(1)
            
            key.is_active = False
            db.commit()
            
            print(f"✅ API key '{key.key_name}' (prefix: {key.key_prefix}) deactivated.")
            
            break
            
        except Exception as e:
            print(f"❌ Error deactivating API key: {e}")
            sys.exit(1)


def main():
    """Main function."""
    parser = argparse.ArgumentParser(description="Manage API keys for the Agentic Honeypot API")
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Create command
    create_parser = subparsers.add_parser('create', help='Create a new API key')
    create_parser.add_argument('name', help='Human-readable name for the API key')
    create_parser.add_argument('--description', help='Optional description')
    create_parser.add_argument('--rate-limit', type=int, default=1000, help='Rate limit per hour (default: 1000)')
    create_parser.add_argument('--created-by', help='Who created this key')
    create_parser.add_argument('--expires-days', type=int, help='Expiration in days from now')
    
    # List command
    list_parser = subparsers.add_parser('list', help='List all API keys')
    
    # Deactivate command
    deactivate_parser = subparsers.add_parser('deactivate', help='Deactivate an API key')
    deactivate_parser.add_argument('prefix', help='Key prefix to deactivate')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    if args.command == 'create':
        asyncio.run(create_api_key(
            key_name=args.name,
            description=args.description,
            rate_limit_per_hour=args.rate_limit,
            created_by=args.created_by,
            expires_days=args.expires_days
        ))
    elif args.command == 'list':
        asyncio.run(list_api_keys())
    elif args.command == 'deactivate':
        asyncio.run(deactivate_api_key(args.prefix))


if __name__ == '__main__':
    main()