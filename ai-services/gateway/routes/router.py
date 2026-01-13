"""
Silver Router Routes

AI-powered route selection using silver ratio weighted scoring.
This is the core intelligence of ADZVPN-Opus routing.
"""

import sys
import random
from pathlib import Path
from typing import List, Optional
from datetime import datetime
from enum import Enum

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from silver_constants import (
    DELTA_S, TAU,
    silver_score, silver_weights_normalized,
)


router = APIRouter(prefix="/router")


# =============================================================================
# MODELS
# =============================================================================

class ServerRegion(str, Enum):
    """Available server regions."""
    US_EAST = "us-east"
    US_WEST = "us-west"
    EU_WEST = "eu-west"
    EU_CENTRAL = "eu-central"
    ASIA_EAST = "asia-east"
    ASIA_SOUTH = "asia-south"


class ServerStatus(str, Enum):
    """Server status."""
    ONLINE = "online"
    DEGRADED = "degraded"
    OFFLINE = "offline"
    MAINTENANCE = "maintenance"


class ServerInfo(BaseModel):
    """VPN server information."""
    id: str
    name: str
    region: ServerRegion
    address: str
    port: int = 51820
    status: ServerStatus = ServerStatus.ONLINE
    latency_ms: float = Field(ge=0)
    bandwidth_mbps: float = Field(ge=0)
    load_percent: float = Field(ge=0, le=100)
    features: List[str] = Field(default_factory=list)


class ScoredServer(BaseModel):
    """Server with silver-weighted score."""
    server: ServerInfo
    score: float
    rank: int
    score_breakdown: dict


class RouteRequest(BaseModel):
    """Route selection request."""
    client_region: Optional[ServerRegion] = None
    preferred_regions: List[ServerRegion] = Field(default_factory=list)
    min_bandwidth_mbps: float = Field(default=0, ge=0)
    max_latency_ms: float = Field(default=1000, ge=0)
    required_features: List[str] = Field(default_factory=list)
    exclude_servers: List[str] = Field(default_factory=list)


class RouteResponse(BaseModel):
    """Route selection response."""
    recommended: ScoredServer
    alternatives: List[ScoredServer]
    total_servers: int
    filtered_count: int
    selection_time_ms: float


class ServerPool(BaseModel):
    """Server pool for batch operations."""
    servers: List[ServerInfo]


class PoolScoreResponse(BaseModel):
    """Batch scoring response."""
    scored_servers: List[ScoredServer]
    best_server: ScoredServer
    average_score: float
    score_distribution: dict


# =============================================================================
# MOCK SERVER DATA (In production, this comes from monitoring)
# =============================================================================

MOCK_SERVERS: List[ServerInfo] = [
    ServerInfo(
        id="sv-us-east-1",
        name="New York 1",
        region=ServerRegion.US_EAST,
        address="nyc1.silver.vpn",
        latency_ms=25,
        bandwidth_mbps=1000,
        load_percent=45,
        features=["streaming", "p2p"],
    ),
    ServerInfo(
        id="sv-us-east-2",
        name="New York 2",
        region=ServerRegion.US_EAST,
        address="nyc2.silver.vpn",
        latency_ms=28,
        bandwidth_mbps=800,
        load_percent=62,
        features=["streaming"],
    ),
    ServerInfo(
        id="sv-us-west-1",
        name="Los Angeles 1",
        region=ServerRegion.US_WEST,
        address="lax1.silver.vpn",
        latency_ms=45,
        bandwidth_mbps=1200,
        load_percent=35,
        features=["streaming", "p2p", "gaming"],
    ),
    ServerInfo(
        id="sv-eu-west-1",
        name="London 1",
        region=ServerRegion.EU_WEST,
        address="lon1.silver.vpn",
        latency_ms=80,
        bandwidth_mbps=900,
        load_percent=55,
        features=["streaming", "p2p"],
    ),
    ServerInfo(
        id="sv-eu-central-1",
        name="Frankfurt 1",
        region=ServerRegion.EU_CENTRAL,
        address="fra1.silver.vpn",
        latency_ms=95,
        bandwidth_mbps=1100,
        load_percent=40,
        features=["streaming", "p2p", "gaming"],
    ),
    ServerInfo(
        id="sv-asia-east-1",
        name="Tokyo 1",
        region=ServerRegion.ASIA_EAST,
        address="tyo1.silver.vpn",
        latency_ms=150,
        bandwidth_mbps=800,
        load_percent=70,
        features=["streaming", "gaming"],
    ),
    ServerInfo(
        id="sv-asia-south-1",
        name="Singapore 1",
        region=ServerRegion.ASIA_SOUTH,
        address="sin1.silver.vpn",
        latency_ms=180,
        bandwidth_mbps=600,
        load_percent=50,
        features=["streaming"],
    ),
]


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def score_server(server: ServerInfo) -> ScoredServer:
    """Calculate silver-weighted score for a server."""
    # Base silver score
    base_score = silver_score(
        server.latency_ms,
        server.bandwidth_mbps,
        server.load_percent,
    )

    # Status penalty
    status_multiplier = {
        ServerStatus.ONLINE: 1.0,
        ServerStatus.DEGRADED: 0.7,
        ServerStatus.OFFLINE: 0.0,
        ServerStatus.MAINTENANCE: 0.0,
    }[server.status]

    final_score = base_score * status_multiplier

    # Score breakdown
    latency_component = 1.0 / (1.0 + server.latency_ms / (TAU * 100))
    bandwidth_component = min(server.bandwidth_mbps / (DELTA_S * 100), 1.0)
    load_component = (100.0 - server.load_percent) / 100.0

    return ScoredServer(
        server=server,
        score=final_score,
        rank=0,  # Set later
        score_breakdown={
            "latency_score": latency_component,
            "bandwidth_score": bandwidth_component,
            "load_score": load_component,
            "status_multiplier": status_multiplier,
            "weights": {
                "latency": DELTA_S,
                "bandwidth": TAU,
                "load": 1.0,
            },
        },
    )


def filter_servers(
    servers: List[ServerInfo],
    request: RouteRequest,
) -> List[ServerInfo]:
    """Filter servers based on request criteria."""
    filtered = []

    for server in servers:
        # Skip offline/maintenance
        if server.status in [ServerStatus.OFFLINE, ServerStatus.MAINTENANCE]:
            continue

        # Skip excluded servers
        if server.id in request.exclude_servers:
            continue

        # Check minimum bandwidth
        if server.bandwidth_mbps < request.min_bandwidth_mbps:
            continue

        # Check maximum latency
        if server.latency_ms > request.max_latency_ms:
            continue

        # Check required features
        if request.required_features:
            if not all(f in server.features for f in request.required_features):
                continue

        # Check preferred regions (if specified, filter to those)
        if request.preferred_regions:
            if server.region not in request.preferred_regions:
                continue

        filtered.append(server)

    return filtered


def rank_servers(scored: List[ScoredServer]) -> List[ScoredServer]:
    """Sort and rank servers by score."""
    # Sort by score descending
    sorted_servers = sorted(scored, key=lambda s: s.score, reverse=True)

    # Assign ranks
    for i, server in enumerate(sorted_servers):
        server.rank = i + 1

    return sorted_servers


# =============================================================================
# ROUTES
# =============================================================================

@router.get("/servers", response_model=List[ServerInfo])
async def list_servers(
    region: Optional[ServerRegion] = Query(default=None, description="Filter by region"),
    status: Optional[ServerStatus] = Query(default=None, description="Filter by status"),
):
    """
    List all available VPN servers.

    Optionally filter by region or status.
    """
    servers = MOCK_SERVERS.copy()

    if region:
        servers = [s for s in servers if s.region == region]

    if status:
        servers = [s for s in servers if s.status == status]

    return servers


@router.get("/servers/{server_id}", response_model=ServerInfo)
async def get_server(server_id: str):
    """Get a specific server by ID."""
    for server in MOCK_SERVERS:
        if server.id == server_id:
            return server

    raise HTTPException(status_code=404, detail=f"Server {server_id} not found")


@router.get("/servers/{server_id}/score", response_model=ScoredServer)
async def score_single_server(server_id: str):
    """
    Get silver-weighted score for a specific server.

    Score is calculated using:
    - Latency (weight: δ_S = 2.414)
    - Bandwidth (weight: τ = 1.414)
    - Load (weight: 1.0)
    """
    for server in MOCK_SERVERS:
        if server.id == server_id:
            scored = score_server(server)
            scored.rank = 1
            return scored

    raise HTTPException(status_code=404, detail=f"Server {server_id} not found")


@router.post("/select", response_model=RouteResponse)
async def select_route(request: RouteRequest):
    """
    Select optimal VPN route using silver-weighted AI scoring.

    The algorithm:
    1. Filter servers by criteria (region, bandwidth, latency, features)
    2. Calculate silver-weighted score for each server
    3. Rank servers by score
    4. Return best server with alternatives

    Silver scoring uses:
    - δ_S (2.414) weight for latency (most important)
    - τ (1.414) weight for bandwidth
    - 1.0 weight for load

    Higher score = better route.
    """
    import time
    start = time.time()

    # Filter servers
    filtered = filter_servers(MOCK_SERVERS, request)

    if not filtered:
        raise HTTPException(
            status_code=404,
            detail="No servers match the specified criteria",
        )

    # Score all servers
    scored = [score_server(s) for s in filtered]

    # Rank by score
    ranked = rank_servers(scored)

    elapsed_ms = (time.time() - start) * 1000

    return RouteResponse(
        recommended=ranked[0],
        alternatives=ranked[1:4],  # Top 3 alternatives
        total_servers=len(MOCK_SERVERS),
        filtered_count=len(filtered),
        selection_time_ms=elapsed_ms,
    )


@router.post("/score-pool", response_model=PoolScoreResponse)
async def score_server_pool(pool: ServerPool):
    """
    Batch score a pool of servers.

    Useful for custom server lists or testing.
    """
    if not pool.servers:
        raise HTTPException(status_code=400, detail="Server pool cannot be empty")

    # Score all servers
    scored = [score_server(s) for s in pool.servers]

    # Rank
    ranked = rank_servers(scored)

    # Calculate stats
    scores = [s.score for s in ranked]
    avg_score = sum(scores) / len(scores)

    # Distribution buckets
    distribution = {
        "excellent (>0.8)": len([s for s in scores if s > 0.8]),
        "good (0.6-0.8)": len([s for s in scores if 0.6 <= s <= 0.8]),
        "fair (0.4-0.6)": len([s for s in scores if 0.4 <= s < 0.6]),
        "poor (<0.4)": len([s for s in scores if s < 0.4]),
    }

    return PoolScoreResponse(
        scored_servers=ranked,
        best_server=ranked[0],
        average_score=avg_score,
        score_distribution=distribution,
    )


@router.get("/weights")
async def get_routing_weights():
    """
    Get current silver routing weights.

    These weights determine how latency, bandwidth, and load
    contribute to the final route score.
    """
    return {
        "algorithm": "silver-weighted-routing",
        "version": "1.0.0",
        "weights": {
            "latency": {
                "value": DELTA_S,
                "name": "delta_s",
                "description": "Silver ratio (1 + √2) - highest priority",
            },
            "bandwidth": {
                "value": TAU,
                "name": "tau",
                "description": "√2 - medium priority",
            },
            "load": {
                "value": 1.0,
                "name": "unit",
                "description": "Base weight - lowest priority",
            },
        },
        "formula": "score = (lat_score * δ_S + bw_score * τ + load_score * 1) / (δ_S + τ + 1)",
        "total_weight": DELTA_S + TAU + 1.0,
    }


@router.post("/simulate")
async def simulate_routing(
    count: int = Query(default=100, ge=1, le=1000, description="Number of simulations"),
):
    """
    Simulate route selections to analyze distribution.

    Runs multiple route selections with slight random variations
    to see how the silver algorithm distributes load.
    """
    selections = {}

    for _ in range(count):
        # Add slight random variation to server metrics
        varied_servers = []
        for server in MOCK_SERVERS:
            varied = server.model_copy()
            varied.latency_ms *= random.uniform(0.9, 1.1)
            varied.load_percent = min(100, varied.load_percent * random.uniform(0.9, 1.1))
            varied_servers.append(varied)

        # Score and select
        scored = [score_server(s) for s in varied_servers]
        ranked = rank_servers(scored)
        winner_id = ranked[0].server.id

        selections[winner_id] = selections.get(winner_id, 0) + 1

    # Calculate percentages
    distribution = {
        server_id: {
            "count": count,
            "percentage": (count / sum(selections.values())) * 100,
        }
        for server_id, count in sorted(
            selections.items(),
            key=lambda x: x[1],
            reverse=True,
        )
    }

    return {
        "simulations": count,
        "distribution": distribution,
        "most_selected": max(selections, key=selections.get),
        "algorithm": "silver-weighted-routing",
    }
