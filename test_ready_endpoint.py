#!/usr/bin/env python3
"""
Quick test for the ready endpoint.
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


async def test_ready_endpoint():
    """Test the ready endpoint."""
    print("Testing ready endpoint...")
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get("http://localhost:8000/ready", timeout=5.0)
            print(f"Status Code: {response.status_code}")
            print(f"Response: {response.json()}")
            return response.status_code == 200
    except Exception as e:
        print(f"Error testing ready endpoint: {e}")
        return False


def run_server():
    """Run the server in a separate process."""
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )


async def main():
    """Main test function."""
    print("Starting ready endpoint test...")
    
    # Start server in background process
    server_process = multiprocessing.Process(target=run_server)
    server_process.start()
    
    try:
        # Wait for server to start
        print("Waiting for server to start...")
        await asyncio.sleep(3)
        
        # Test ready endpoint
        success = await test_ready_endpoint()
        
        if success:
            print("✅ Ready endpoint test PASSED")
        else:
            print("❌ Ready endpoint test FAILED")
        
    finally:
        # Clean up
        server_process.terminate()
        server_process.join(timeout=5)
        if server_process.is_alive():
            server_process.kill()
        print("Server stopped")


if __name__ == "__main__":
    asyncio.run(main())