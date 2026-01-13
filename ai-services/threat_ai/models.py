"""
Threat AI Models

Data models for threat detection.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional


class ThreatLevel(Enum):
    """Threat severity level."""
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def to_score(self) -> float:
        """Convert to numeric score (0-1)."""
        return {
            ThreatLevel.SAFE: 0.0,
            ThreatLevel.LOW: 0.25,
            ThreatLevel.MEDIUM: 0.5,
            ThreatLevel.HIGH: 0.75,
            ThreatLevel.CRITICAL: 1.0,
        }[self]

    @classmethod
    def from_score(cls, score: float) -> "ThreatLevel":
        """Create from numeric score."""
        if score < 0.2:
            return cls.SAFE
        elif score < 0.4:
            return cls.LOW
        elif score < 0.6:
            return cls.MEDIUM
        elif score < 0.8:
            return cls.HIGH
        else:
            return cls.CRITICAL


class ThreatCategory(Enum):
    """Category of threat."""
    NONE = "none"
    MALWARE = "malware"
    PHISHING = "phishing"
    BOTNET = "botnet"
    CRYPTO_MINING = "crypto_mining"
    DATA_EXFILTRATION = "data_exfiltration"
    COMMAND_CONTROL = "command_control"
    SPAM = "spam"
    SCANNER = "scanner"
    BRUTE_FORCE = "brute_force"
    DDoS = "ddos"
    SUSPICIOUS = "suspicious"
    UNKNOWN = "unknown"


@dataclass
class DomainInfo:
    """Information about a domain."""
    domain: str
    # Classification
    threat_level: ThreatLevel = ThreatLevel.SAFE
    threat_category: ThreatCategory = ThreatCategory.NONE
    confidence: float = 0.0
    # Domain features
    length: int = 0
    entropy: float = 0.0
    has_ip: bool = False
    subdomain_count: int = 0
    tld: str = ""
    # Reputation
    reputation_score: float = 1.0  # 0 = bad, 1 = good
    is_known_bad: bool = False
    is_known_good: bool = False
    # Timestamps
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "domain": self.domain,
            "threat_level": self.threat_level.value,
            "threat_category": self.threat_category.value,
            "confidence": self.confidence,
            "features": {
                "length": self.length,
                "entropy": self.entropy,
                "has_ip": self.has_ip,
                "subdomain_count": self.subdomain_count,
                "tld": self.tld,
            },
            "reputation_score": self.reputation_score,
            "is_known_bad": self.is_known_bad,
            "is_known_good": self.is_known_good,
        }


@dataclass
class TrafficFeatures:
    """
    Traffic features for analysis.

    Features are designed to detect anomalies without
    inspecting actual packet contents (privacy-preserving).
    """
    # Session info
    session_id: str = ""
    client_id: str = ""

    # Volume metrics
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0

    # Timing metrics
    duration_secs: float = 0.0
    avg_packet_interval_ms: float = 0.0
    packet_interval_variance: float = 0.0

    # Pattern metrics
    bytes_ratio: float = 0.0  # sent/received ratio
    packet_size_avg: float = 0.0
    packet_size_variance: float = 0.0

    # Connection metrics
    unique_destinations: int = 0
    connection_count: int = 0
    failed_connections: int = 0

    # Time-based
    hour_of_day: int = 0
    is_weekend: bool = False

    def to_feature_vector(self) -> List[float]:
        """Convert to numeric feature vector for ML."""
        return [
            float(self.bytes_sent),
            float(self.bytes_received),
            float(self.packets_sent),
            float(self.packets_received),
            self.duration_secs,
            self.avg_packet_interval_ms,
            self.packet_interval_variance,
            self.bytes_ratio,
            self.packet_size_avg,
            self.packet_size_variance,
            float(self.unique_destinations),
            float(self.connection_count),
            float(self.failed_connections),
            float(self.hour_of_day),
            float(self.is_weekend),
        ]

    @staticmethod
    def feature_names() -> List[str]:
        """Get feature names for interpretability."""
        return [
            "bytes_sent",
            "bytes_received",
            "packets_sent",
            "packets_received",
            "duration_secs",
            "avg_packet_interval_ms",
            "packet_interval_variance",
            "bytes_ratio",
            "packet_size_avg",
            "packet_size_variance",
            "unique_destinations",
            "connection_count",
            "failed_connections",
            "hour_of_day",
            "is_weekend",
        ]


@dataclass
class ThreatAlert:
    """A threat detection alert."""
    # Identity
    alert_id: str = ""
    timestamp: datetime = field(default_factory=datetime.utcnow)

    # Classification
    threat_level: ThreatLevel = ThreatLevel.SAFE
    threat_category: ThreatCategory = ThreatCategory.NONE
    confidence: float = 0.0

    # Context
    source: str = ""  # What generated this alert
    session_id: str = ""
    client_id: str = ""

    # Details
    description: str = ""
    indicators: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)

    # Related data
    domain: Optional[str] = None
    ip_address: Optional[str] = None
    raw_features: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp.isoformat(),
            "threat_level": self.threat_level.value,
            "threat_category": self.threat_category.value,
            "confidence": self.confidence,
            "source": self.source,
            "session_id": self.session_id,
            "client_id": self.client_id,
            "description": self.description,
            "indicators": self.indicators,
            "recommendations": self.recommendations,
            "domain": self.domain,
            "ip_address": self.ip_address,
        }


@dataclass
class ThreatReport:
    """Comprehensive threat report for a session."""
    # Session info
    session_id: str = ""
    client_id: str = ""
    report_time: datetime = field(default_factory=datetime.utcnow)

    # Overall assessment
    overall_threat_level: ThreatLevel = ThreatLevel.SAFE
    overall_score: float = 0.0

    # Component scores
    domain_score: float = 0.0
    traffic_score: float = 0.0
    anomaly_score: float = 0.0

    # Alerts
    alerts: List[ThreatAlert] = field(default_factory=list)

    # Statistics
    domains_checked: int = 0
    domains_flagged: int = 0
    traffic_samples: int = 0
    anomalies_detected: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "session_id": self.session_id,
            "client_id": self.client_id,
            "report_time": self.report_time.isoformat(),
            "overall_threat_level": self.overall_threat_level.value,
            "overall_score": self.overall_score,
            "component_scores": {
                "domain": self.domain_score,
                "traffic": self.traffic_score,
                "anomaly": self.anomaly_score,
            },
            "alerts": [a.to_dict() for a in self.alerts],
            "statistics": {
                "domains_checked": self.domains_checked,
                "domains_flagged": self.domains_flagged,
                "traffic_samples": self.traffic_samples,
                "anomalies_detected": self.anomalies_detected,
            },
        }
