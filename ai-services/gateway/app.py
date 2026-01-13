"""
ADZVPN-Opus AI Gateway

Main FastAPI application for AI services.

Created by: ADZ (Alexander David Zalewski) & Claude Opus 4.5
"""

import sys
from pathlib import Path
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# Add parent directory for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from silver_constants import (
    DELTA_S, TAU, ETA,
    verify_palindrome_identity,
    verify_unit_magnitude,
)
from .config import get_settings


# =============================================================================
# LIFESPAN
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan handler."""
    settings = get_settings()

    # Startup
    print(BANNER)
    print(f"Starting ADZVPN-Opus AI Gateway v{settings.api_version}")
    print(f"Silver Constants: δ_S={DELTA_S:.6f}, τ={TAU:.6f}, η={ETA:.6f}")
    print(f"Palindrome Identity Valid: {verify_palindrome_identity()}")
    print(f"Unit Magnitude Valid: {verify_unit_magnitude()}")
    print()

    # Verify silver math on startup
    assert verify_palindrome_identity(), "Silver palindrome identity failed!"
    assert verify_unit_magnitude(), "Silver unit magnitude failed!"

    yield

    # Shutdown
    print("Shutting down ADZVPN-Opus AI Gateway")


# =============================================================================
# APP FACTORY
# =============================================================================

BANNER = r"""
    ___    ____  _____    ______ _   __
   /   |  / __ \/__  /   / ____/| | / /____  ____
  / /| | / / / /  / /   / /     | |/ // __ \/ __ \
 / ___ |/ /_/ /  / /__ / /___   |   // /_/ / / / /
/_/  |_/_____/  /____/ \____/   |_| / .___/_/ /_/
                                   /_/
     ___    ____   ______      __
    /   |  /  _/  / ____/___ _/ /____  _      ______ ___  __
   / /| |  / /   / / __/ __ `/ __/ _ \| | /| / / __ `/ / / /
  / ___ |_/ /   / /_/ / /_/ / /_/  __/| |/ |/ / /_/ / /_/ /
 /_/  |_/___/   \____/\__,_/\__/\___/ |__/|__/\__,_/\__, /
                                                   /____/
      Silver Ratio AI Services (δ_S = 1 + √2)
"""


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    settings = get_settings()

    app = FastAPI(
        title=settings.api_title,
        version=settings.api_version,
        description="AI-powered services for ADZVPN-Opus using Silver Ratio mathematics",
        lifespan=lifespan,
        docs_url=f"{settings.api_prefix}/docs",
        redoc_url=f"{settings.api_prefix}/redoc",
        openapi_url=f"{settings.api_prefix}/openapi.json",
    )

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Include routers
    from .routes import health, silver, router as silver_router, threat, privacy, assistant

    app.include_router(health.router, prefix=settings.api_prefix, tags=["Health"])
    app.include_router(silver.router, prefix=settings.api_prefix, tags=["Silver Math"])
    app.include_router(silver_router.router, prefix=settings.api_prefix, tags=["Silver Router"])
    app.include_router(threat.router, prefix=settings.api_prefix, tags=["Threat Detection"])
    app.include_router(privacy.router, prefix=settings.api_prefix, tags=["Privacy AI"])
    app.include_router(assistant.router, prefix=settings.api_prefix, tags=["Chat Assistant"])

    # Exception handler
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        return JSONResponse(
            status_code=500,
            content={
                "error": "Internal server error",
                "detail": str(exc) if settings.debug else "An error occurred",
            },
        )

    return app


# Create default app instance
app = create_app()


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    import uvicorn

    settings = get_settings()
    uvicorn.run(
        "app:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
    )
