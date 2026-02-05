#!/usr/bin/env python3
"""
Startup script for the application.
"""

import os
import sys
import subprocess

def main():
    """Main startup function."""
    # Get port from environment or use default
    port = os.environ.get('PORT', '8000')
    
    print(f"Starting server on port {port}")
    
    # Build the command
    cmd = [
        'uvicorn',
        'app.main:app',
        '--host', '0.0.0.0',
        '--port', str(port)
    ]
    
    print(f"Running command: {' '.join(cmd)}")
    
    # Execute the command
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error starting server: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("Server stopped by user")
        sys.exit(0)

if __name__ == "__main__":
    main()