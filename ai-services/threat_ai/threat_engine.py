"""
Threat Engine

Unified threat detection engine combining:
- Domain classification
- Traffic analysis
- Anomaly detection

Uses silver ratio for score weighting and thresholds.

Created by: ADZ (Alexander David Zalewski) & Claude Opus 4.5
"""

import sys
import uuid
from pathlib import Path
from typing import List, Dict, Optional, Set
from datetime import datetime, timedelta
from dataclasses import dataclass, field

# Add parent for silver constants
sys.path.insert(0, str(Path(__file__).parent.parent))
from silver_constants import DELTA_S, TAU, ETA

from .models import (
    ThreatLevel,
    ThreatCategory,
    DomainInfo,
    TrafficFeatures,
    ThreatAlert,
    ThreatReport,
)
from .domain_classifier import DomainClassifier
from .traffic_analyzer import TrafficAnalyzer
from .anomaly_detector import AnomalyDetector


@dataclass
class ThreatEngineConfig:
    """Configuration for the threat engine."""
    # Enable/disable components
    enable_domain_classifier: bool = True
    enable_traffic_analyzer: bool = True
    enable_anomaly_detector: bool = True

    # Thresholds (silver-scaled)
    alert_threshold: float = 0.4  # Score above this triggers alert
    block_threshold: float = 0.8  # Score above this triggers block

    # Silver weights for combining scores
    domain_weight: float = DELTA_S  # Highest priority
    traffic_weight: float = TAU     # Medium priority
    anomaly_weight: float = 1.0     # Base priority

    # Rate limiting
    max_alerts_per_minute: int = 100
    alert_cooldown_secs: int = 60

    # History
    max_alert_history: int = 10000
    max_domain_cache: int = 50000


class ThreatEngine:
    """
    Unified threat detection engine.

    Combines domain classification, traffic analysis, and anomaly
    detection with silver-weighted scoring.
    """

    def __init__(self, config: Optional[ThreatEngineConfig] = None):
        """
        Initialize the threat engine.

        Args:
            config: Engine configuration
        """
        self.config = config or ThreatEngineConfig()

        # Initialize components
        self.domain_classifier = DomainClassifier()
        self.traffic_analyzer = TrafficAnalyzer()
        self.anomaly_detector = AnomalyDetector()

        # State
        self._alert_history: List[ThreatAlert] = []
        self._domain_cache: Dict[str, DomainInfo] = {}
        self._blocked_domains: Set[str] = set()
        self._blocked_clients: Set[str] = set()

        # Rate limiting
        self._alert_counts: Dict[str, List[datetime]] = {}

        # Statistics
        self._stats = {
            "domains_checked": 0,
            "domains_blocked": 0,
            "traffic_analyzed": 0,
            "anomalies_detected": 0,
            "alerts_generated": 0,
        }

    def analyze_domain(self, domain: str) -> DomainInfo:
        """
        Analyze a domain for threats.

        Uses caching to avoid repeated analysis.
        """
        # Check cache
        if domain in self._domain_cache:
            return self._domain_cache[domain]

        # Classify domain
        info = self.domain_classifier.classify(domain)
        self._stats["domains_checked"] += 1

        # Cache result
        self._cache_domain(domain, info)

        # Auto-block if critical
        if info.threat_level == ThreatLevel.CRITICAL:
            self._blocked_domains.add(domain)
            self._stats["domains_blocked"] += 1

        return info

    def analyze_traffic(
        self,
        features: TrafficFeatures,
        domains: Optional[List[str]] = None,
    ) -> ThreatReport:
        """
        Analyze traffic for threats.

        Args:
            features: Traffic features to analyze
            domains: Optional list of domains accessed

        Returns:
            Comprehensive threat report
        """
        alerts: List[ThreatAlert] = []
        domain_score = 0.0
        traffic_score = 0.0
        anomaly_score = 0.0

        # Domain analysis
        domains_flagged = 0
        if self.config.enable_domain_classifier and domains:
            for domain in domains:
                info = self.analyze_domain(domain)
                if info.threat_level.to_score() > self.config.alert_threshold:
                    domains_flagged += 1
                    alerts.append(self._create_domain_alert(info, features))

            if domains:
                domain_score = max(
                    self.analyze_domain(d).threat_level.to_score()
                    for d in domains
                )

        # Traffic analysis
        if self.config.enable_traffic_analyzer:
            traffic_alerts = self.traffic_analyzer.analyze(features)
            alerts.extend(traffic_alerts)
            self._stats["traffic_analyzed"] += 1

            if traffic_alerts:
                traffic_score = max(a.threat_level.to_score() for a in traffic_alerts)

        # Anomaly detection
        if self.config.enable_anomaly_detector:
            anomaly_alert = self.anomaly_detector.analyze(features)
            if anomaly_alert:
                alerts.append(anomaly_alert)
                self._stats["anomalies_detected"] += 1
                anomaly_score = anomaly_alert.threat_level.to_score()

        # Calculate overall score (silver-weighted)
        total_weight = (
            self.config.domain_weight +
            self.config.traffic_weight +
            self.config.anomaly_weight
        )

        overall_score = (
            domain_score * self.config.domain_weight +
            traffic_score * self.config.traffic_weight +
            anomaly_score * self.config.anomaly_weight
        ) / total_weight

        # Generate alert IDs
        for alert in alerts:
            if not alert.alert_id:
                alert.alert_id = self._generate_alert_id()

        # Record alerts
        self._record_alerts(alerts)

        # Check for blocking
        if overall_score >= self.config.block_threshold:
            self._blocked_clients.add(features.client_id)

        return ThreatReport(
            session_id=features.session_id,
            client_id=features.client_id,
            overall_threat_level=ThreatLevel.from_score(overall_score),
            overall_score=overall_score,
            domain_score=domain_score,
            traffic_score=traffic_score,
            anomaly_score=anomaly_score,
            alerts=alerts,
            domains_checked=len(domains) if domains else 0,
            domains_flagged=domains_flagged,
            traffic_samples=1,
            anomalies_detected=1 if anomaly_score > 0 else 0,
        )

    def check_domain(self, domain: str) -> bool:
        """
        Quick check if domain is allowed.

        Returns True if allowed, False if blocked.
        """
        # Check block list
        if domain in self._blocked_domains:
            return False

        # Analyze domain
        info = self.analyze_domain(domain)

        return info.threat_level.to_score() < self.config.block_threshold

    def check_client(self, client_id: str) -> bool:
        """
        Check if client is allowed.

        Returns True if allowed, False if blocked.
        """
        return client_id not in self._blocked_clients

    def block_domain(self, domain: str, reason: str = "") -> None:
        """Manually block a domain."""
        self._blocked_domains.add(domain)
        self._stats["domains_blocked"] += 1

    def unblock_domain(self, domain: str) -> None:
        """Unblock a domain."""
        self._blocked_domains.discard(domain)

    def block_client(self, client_id: str, reason: str = "") -> None:
        """Block a client."""
        self._blocked_clients.add(client_id)

    def unblock_client(self, client_id: str) -> None:
        """Unblock a client."""
        self._blocked_clients.discard(client_id)

    def get_blocked_domains(self) -> Set[str]:
        """Get set of blocked domains."""
        return self._blocked_domains.copy()

    def get_blocked_clients(self) -> Set[str]:
        """Get set of blocked clients."""
        return self._blocked_clients.copy()

    def get_recent_alerts(self, limit: int = 100) -> List[ThreatAlert]:
        """Get recent alerts."""
        return self._alert_history[-limit:]

    def get_stats(self) -> Dict[str, int]:
        """Get engine statistics."""
        return {
            **self._stats,
            "blocked_domains": len(self._blocked_domains),
            "blocked_clients": len(self._blocked_clients),
            "cached_domains": len(self._domain_cache),
            "alert_history_size": len(self._alert_history),
        }

    def _create_domain_alert(
        self,
        info: DomainInfo,
        features: TrafficFeatures,
    ) -> ThreatAlert:
        """Create alert from domain classification."""
        return ThreatAlert(
            alert_id=self._generate_alert_id(),
            threat_level=info.threat_level,
            threat_category=info.threat_category,
            confidence=info.confidence,
            source="domain_classifier",
            session_id=features.session_id,
            client_id=features.client_id,
            description=f"Suspicious domain detected: {info.domain}",
            indicators=[
                f"Threat level: {info.threat_level.value}",
                f"Category: {info.threat_category.value}",
                f"Entropy: {info.entropy:.2f}",
                f"Reputation: {info.reputation_score:.2f}",
            ],
            recommendations=[
                "Block access to this domain",
                "Review client activity",
            ],
            domain=info.domain,
        )

    def _cache_domain(self, domain: str, info: DomainInfo) -> None:
        """Cache domain analysis result."""
        self._domain_cache[domain] = info

        # Trim cache if needed
        if len(self._domain_cache) > self.config.max_domain_cache:
            # Remove oldest entries (simple FIFO)
            keys = list(self._domain_cache.keys())
            for key in keys[:len(keys) // 4]:
                del self._domain_cache[key]

    def _record_alerts(self, alerts: List[ThreatAlert]) -> None:
        """Record alerts in history."""
        for alert in alerts:
            self._alert_history.append(alert)
            self._stats["alerts_generated"] += 1

        # Trim history
        if len(self._alert_history) > self.config.max_alert_history:
            self._alert_history = self._alert_history[-self.config.max_alert_history:]

    def _generate_alert_id(self) -> str:
        """Generate unique alert ID."""
        return f"alert-{uuid.uuid4().hex[:12]}"

    def _check_rate_limit(self, client_id: str) -> bool:
        """Check if client is within rate limit for alerts."""
        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=60)

        if client_id not in self._alert_counts:
            self._alert_counts[client_id] = []

        # Clean old entries
        self._alert_counts[client_id] = [
            t for t in self._alert_counts[client_id]
            if t > cutoff
        ]

        return len(self._alert_counts[client_id]) < self.config.max_alerts_per_minute

    def train_anomaly_detector(self, samples: List[TrafficFeatures]) -> bool:
        """Train the anomaly detector on normal traffic."""
        return self.anomaly_detector.train(samples)


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def quick_domain_check(domain: str) -> ThreatLevel:
    """Quick check of domain threat level."""
    engine = ThreatEngine()
    info = engine.analyze_domain(domain)
    return info.threat_level


def quick_traffic_check(features: TrafficFeatures) -> ThreatLevel:
    """Quick check of traffic threat level."""
    engine = ThreatEngine()
    report = engine.analyze_traffic(features)
    return report.overall_threat_level
