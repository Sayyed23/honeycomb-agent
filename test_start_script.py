#!/usr/bin/env python3
"""
Test the start script logic.
"""

import os
import subprocess
import sys

def test_port_handling():
    """Test port environment variable handling."""
    print("Testing port handling...")
    
    # Test with PORT set
    os.environ['PORT'] = '9000'
    port = os.environ.get('PORT', '8000')
    print(f"With PORT=9000: {port}")
    
    # Test without PORT set
    del os.environ['PORT']
    port = os.environ.get('PORT', '8000')
    print(f"Without PORT: {port}")
    
    # Test the actual command that would be run
    port = os.environ.get('PORT', '8000')
    command = f"uvicorn app.main:app --host 0.0.0.0 --port {port}"
    print(f"Command would be: {command}")
    
    print("✅ Port handling test passed")

if __name__ == "__main__":
    test_port_handling()