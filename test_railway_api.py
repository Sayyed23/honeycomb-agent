#!/usr/bin/env python3
"""
Railway deployment test script to verify the honeypot API works after deployment.
"""

import asyncio
import aiohttp
import json
import sys
from datetime import datetime

# Test configuration
BASE_URL = "https://1-production-fc5b.up.railway.app"
API_KEY = "iR3PgIodG2xKOCsKa7eNK6HrVKMNHOpzQmfDD6wPs"

async def test_health_endpoint():
    """Test the health endpoint."""
    print("🔍 Testing health endpoint...")
    
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(f"{BASE_URL}/health", timeout=30) as response:
                if response.st