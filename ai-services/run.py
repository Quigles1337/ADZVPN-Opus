#!/usr/bin/env python3
"""
ADZVPN-Opus AI Services Runner

Start the AI Gateway server.

Usage:
    python run.py
    python run.py --port 8080
    python run.py --debug
"""

import argparse
import uvicorn


def main():
    parser = argparse.ArgumentParser(description="ADZVPN-Opus AI Gateway")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind to")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload")

    args = parser.parse_args()

    print(f"Starting ADZVPN-Opus AI Gateway on {args.host}:{args.port}")

    uvicorn.run(
        "gateway.app:app",
        host=args.host,
        port=args.port,
        reload=args.reload or args.debug,
        log_level="debug" if args.debug else "info",
    )


if __name__ == "__main__":
    main()
