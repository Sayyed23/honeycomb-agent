#!/usr/bin/env python3
"""
Simple script to test the health endpoint locally.
"""

import asyncio
import httpx
import uvicorn
import multiprocessing
import time
import sys
import os

# Add the app directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.main import app


async def test_health_endpoint():
    """Test the health endpoint."""
    print("Testing health endpoint...")
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get("http://localhost:8000/health", timeout=10.0)
            print(f"Status Code: {response.status_code}")
            print(f"Response: {response.json()}")
            return response.status_code == 200
    except Exception as e:
        print(f"Error testing health endpoint: {e}")
        return False


def run_server():
    """Run the server in a separate process."""
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        log_level="info",
        access_log=True
    )


async def main():
    """Main test function."""
    print("Starting local health check test...")
    
    # Start server in background process
    server_process = multiprocessing.Process(target=run_server)
    server_process.start()
    
    try:
        # Wait for server to start
        print("Waiting for server to start...")
        await asyncio.sleep(5)
        
        # Test health endpoint
        success = await test_health_endpoint()
        
        if success:
            print("✅ Health endpoint test PASSED")
        else:
            print("❌ Health endpoint test FAILED")
        
        # Test root endpoint
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get("http://localhost:8000/", timeout=10.0)
                print(f"Root endpoint status: {response.status_code}")
                print(f"Root response: {response.json()}")
        except Exception as e:
            print(f"Error testing root endpoint: {e}")
        
    finally:
        # Clean up
        server_process.terminate()
        server_process.join(timeout=5)
        if server_process.is_alive():
            server_process.kill()
        print("Server stopped")


if __name__ == "__main__":
    asyncio.run(main())