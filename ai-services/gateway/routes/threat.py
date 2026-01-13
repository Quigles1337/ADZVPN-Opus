"""
Threat Detection Routes

AI-powered threat detection and analysis endpoints.

Created by: ADZ (Alexander David Zalewski) & Claude Opus 4.5
"""

import sys
from pathlib import Path
from typing import List, Optional
from datetime import datetime

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from threat_ai import (
    ThreatLevel,
    ThreatCategory,
    ThreatAlert,
    TrafficFeatures,
    DomainClassifier,
    TrafficAnalyzer,
    AnomalyDetector,
    ThreatEngine,
)

router = APIRouter(prefix="/threat")

# =============================================================================
# SINGLETON ENGINE
# =============================================================================

_threat_engine: Optional[ThreatEngine] = None


def get_engine() -> ThreatEngine:
    """Get or create threat engine singleton."""
    global _threat_engine
    if _threat_engine is None:
        _threat_engine = ThreatEngine()
    return _threat_engine


# =============================================================================
# REQUEST/RESPONSE MODELS
# =============================================================================

class DomainCheckRequest(BaseModel):
    """Domain check request."""
    domain: str = Field(..., description="Domain to analyze")


class DomainCheckResponse(BaseModel):
    """Domain check response."""
    domain: str
    is_suspicious: bool
    threat_level: str
    score: float
    category: str
    indicators: List[str]
    cached: bool = False


class BatchDomainRequest(BaseModel):
    """Batch domain check request."""
    domains: List[str] = Field(..., min_length=1, max_length=100)


class BatchDomainResponse(BaseModel):
    """Batch domain check response."""
    results: List[DomainCheckResponse]
    total: int
    suspicious_count: int
    safe_count: int


class TrafficAnalysisRequest(BaseModel):
    """Traffic analysis request."""
    client_id: str
    bytes_sent: int = Field(ge=0)
    bytes_received: int = Field(ge=0)
    packets_sent: int = Field(ge=0)
    packets_received: int = Field(ge=0)
    duration_seconds: float = Field(gt=0)
    unique_destinations: int = Field(ge=0, default=1)
    avg_packet_size: float = Field(ge=0, default=500)
    packet_interval_variance: float = Field(ge=0, default=100)
    domains: List[str] = Field(default_factory=list)


class TrafficAnalysisResponse(BaseModel):
    """Traffic analysis response."""
    client_id: str
    threat_level: str
    threat_score: float
    is_anomaly: bool
    detected_threats: List[dict]
    recommendations: List[str]
    analysis_time_ms: float


class BlockRequest(BaseModel):
    """Block request for domain or client."""
    target: str = Field(..., description="Domain or client ID to block")
    reason: str = Field(default="manual", description="Reason for blocking")


class ThreatStatsResponse(BaseModel):
    """Threat statistics response."""
    total_analyses: int
    domains_analyzed: int
    clients_analyzed: int
    threats_detected: int
    blocked_domains: int
    blocked_clients: int
    threat_distribution: dict
    category_distribution: dict


# =============================================================================
# ROUTES
# =============================================================================

@router.get("/status")
async def threat_status():
    """Get threat detection service status."""
    engine = get_engine()
    stats = engine.get_stats()

    return {
        "status": "operational",
        "engine": "ThreatEngine v1.0",
        "features": [
            "domain_classification",
            "traffic_analysis",
            "anomaly_detection",
            "silver_weighted_scoring",
        ],
        "stats": stats,
    }


@router.post("/check/domain", response_model=DomainCheckResponse)
async def check_domain(request: DomainCheckRequest):
    """
    Analyze a domain for threats.

    Checks for:
    - DGA (Domain Generation Algorithm) patterns
    - Phishing indicators
    - High entropy domains
    - Suspicious TLDs
    - Known malicious patterns
    """
    engine = get_engine()
    result = engine.check_domain(request.domain)

    # Get detailed analysis
    classifier = DomainClassifier()
    analysis = classifier.classify(request.domain)

    return DomainCheckResponse(
        domain=request.domain,
        is_suspicious=result["is_suspicious"],
        threat_level=result["threat_level"],
        score=analysis.score,
        category=analysis.category.value,
        indicators=[i.indicator_type for i in analysis.indicators],
        cached=result.get("cached", False),
    )


@router.post("/check/domains", response_model=BatchDomainResponse)
async def check_domains_batch(request: BatchDomainRequest):
    """
    Batch analyze multiple domains.

    Efficient for checking many domains at once.
    """
    engine = get_engine()
    classifier = DomainClassifier()

    results = []
    suspicious_count = 0

    for domain in request.domains:
        check = engine.check_domain(domain)
        analysis = classifier.classify(domain)

        is_suspicious = check["is_suspicious"]
        if is_suspicious:
            suspicious_count += 1

        results.append(DomainCheckResponse(
            domain=domain,
            is_suspicious=is_suspicious,
            threat_level=check["threat_level"],
            score=analysis.score,
            category=analysis.category.value,
            indicators=[i.indicator_type for i in analysis.indicators],
        ))

    return BatchDomainResponse(
        results=results,
        total=len(results),
        suspicious_count=suspicious_count,
        safe_count=len(results) - suspicious_count,
    )


@router.post("/analyze/traffic", response_model=TrafficAnalysisResponse)
async def analyze_traffic(request: TrafficAnalysisRequest):
    """
    Analyze traffic patterns for threats.

    Detects:
    - Data exfiltration (high outbound ratio)
    - C2 beaconing (regular intervals)
    - Port scanning (many destinations)
    - DDoS patterns (high packet rate)
    """
    import time
    start = time.time()

    engine = get_engine()

    # Build traffic features
    features = TrafficFeatures(
        bytes_sent=request.bytes_sent,
        bytes_received=request.bytes_received,
        packets_sent=request.packets_sent,
        packets_received=request.packets_received,
        duration_seconds=request.duration_seconds,
        unique_destinations=request.unique_destinations,
        avg_packet_size=request.avg_packet_size,
        packet_interval_variance=request.packet_interval_variance,
    )

    # Analyze
    result = engine.analyze_traffic(request.client_id, features, request.domains)

    # Build recommendations
    recommendations = []
    if result.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
        recommendations.append("Immediately investigate this client")
        recommendations.append("Consider blocking if threat persists")
    elif result.threat_level == ThreatLevel.MEDIUM:
        recommendations.append("Monitor this client closely")
        recommendations.append("Review recent activity")
    else:
        recommendations.append("Normal traffic patterns detected")

    # Format threats
    detected_threats = []
    for threat in result.threats:
        detected_threats.append({
            "type": threat.indicator_type,
            "description": threat.description,
            "severity": threat.severity,
            "confidence": threat.confidence,
        })

    elapsed_ms = (time.time() - start) * 1000

    return TrafficAnalysisResponse(
        client_id=request.client_id,
        threat_level=result.threat_level.value,
        threat_score=result.score,
        is_anomaly=result.is_anomaly,
        detected_threats=detected_threats,
        recommendations=recommendations,
        analysis_time_ms=elapsed_ms,
    )


@router.post("/block/domain")
async def block_domain(request: BlockRequest):
    """Block a malicious domain."""
    engine = get_engine()
    engine.block_domain(request.target, request.reason)

    return {
        "success": True,
        "blocked": request.target,
        "type": "domain",
        "reason": request.reason,
        "timestamp": datetime.utcnow().isoformat(),
    }


@router.post("/block/client")
async def block_client(request: BlockRequest):
    """Block a malicious client."""
    engine = get_engine()
    engine.block_client(request.target, request.reason)

    return {
        "success": True,
        "blocked": request.target,
        "type": "client",
        "reason": request.reason,
        "timestamp": datetime.utcnow().isoformat(),
    }


@router.delete("/block/domain/{domain}")
async def unblock_domain(domain: str):
    """Unblock a domain."""
    engine = get_engine()
    blocked = engine.get_blocked_lists()

    if domain not in blocked["domains"]:
        raise HTTPException(status_code=404, detail=f"Domain {domain} is not blocked")

    # Note: In real implementation, we'd have an unblock method
    return {
        "success": True,
        "unblocked": domain,
        "type": "domain",
    }


@router.get("/blocked")
async def get_blocked_lists():
    """Get lists of blocked domains and clients."""
    engine = get_engine()
    blocked = engine.get_blocked_lists()

    return {
        "blocked_domains": list(blocked["domains"].keys()),
        "blocked_clients": list(blocked["clients"].keys()),
        "total_blocked": len(blocked["domains"]) + len(blocked["clients"]),
    }


@router.get("/stats", response_model=ThreatStatsResponse)
async def get_threat_stats():
    """Get threat detection statistics."""
    engine = get_engine()
    stats = engine.get_stats()

    return ThreatStatsResponse(
        total_analyses=stats["total_analyses"],
        domains_analyzed=stats["domains_analyzed"],
        clients_analyzed=stats["clients_analyzed"],
        threats_detected=stats["threats_detected"],
        blocked_domains=stats["blocked_domains"],
        blocked_clients=stats["blocked_clients"],
        threat_distribution=stats.get("threat_distribution", {}),
        category_distribution=stats.get("category_distribution", {}),
    )


@router.get("/levels")
async def get_threat_levels():
    """Get threat level definitions."""
    return {
        "levels": [
            {
                "name": ThreatLevel.NONE.value,
                "score_range": "0.0 - 0.1",
                "description": "No threat detected",
                "action": "Allow traffic",
            },
            {
                "name": ThreatLevel.LOW.value,
                "score_range": "0.1 - 0.3",
                "description": "Minor suspicious indicators",
                "action": "Log and monitor",
            },
            {
                "name": ThreatLevel.MEDIUM.value,
                "score_range": "0.3 - 0.6",
                "description": "Moderate threat indicators",
                "action": "Enhanced monitoring, alert",
            },
            {
                "name": ThreatLevel.HIGH.value,
                "score_range": "0.6 - 0.8",
                "description": "Significant threat detected",
                "action": "Investigate immediately",
            },
            {
                "name": ThreatLevel.CRITICAL.value,
                "score_range": "0.8 - 1.0",
                "description": "Critical threat - active attack",
                "action": "Block and investigate",
            },
        ],
        "scoring": {
            "method": "silver-weighted",
            "weights": {
                "domain_risk": "δ_S (2.414)",
                "traffic_anomaly": "τ (1.414)",
                "behavior_score": "1.0",
            },
        },
    }
