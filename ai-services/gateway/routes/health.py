"""
Health Check Routes

Endpoints for service health monitoring.
"""

import sys
from pathlib import Path
from datetime import datetime

from fastapi import APIRouter
from pydantic import BaseModel

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from silver_constants import DELTA_S, TAU, ETA, verify_palindrome_identity


router = APIRouter()


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    service: str
    version: str
    timestamp: str
    silver_valid: bool
    constants: dict


class ReadyResponse(BaseModel):
    """Readiness check response."""
    ready: bool
    services: dict


@router.get("/health", response_model=HealthResponse)
async def health_check():
    """
    Health check endpoint.

    Returns service status and silver constant verification.
    """
    return HealthResponse(
        status="healthy",
        service="adzvpn-ai-gateway",
        version="1.0.0",
        timestamp=datetime.utcnow().isoformat(),
        silver_valid=verify_palindrome_identity(),
        constants={
            "delta_s": DELTA_S,
            "tau": TAU,
            "eta": ETA,
        },
    )


@router.get("/ready", response_model=ReadyResponse)
async def readiness_check():
    """
    Readiness check endpoint.

    Returns status of all AI services.
    """
    # TODO: Actually check service status
    return ReadyResponse(
        ready=True,
        services={
            "silver_router": True,
            "threat_ai": True,
            "privacy_ai": True,
            "assistant": False,  # Requires Ollama
        },
    )


@router.get("/ping")
async def ping():
    """Simple ping endpoint."""
    return {"pong": True, "delta_s": DELTA_S}
