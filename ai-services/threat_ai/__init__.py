"""
ADZVPN-Opus Threat AI

AI-powered threat detection for VPN traffic.

Components:
- DomainClassifier: Classify domains as safe/suspicious/malicious
- TrafficAnalyzer: Analyze traffic patterns for threats
- AnomalyDetector: Detect anomalous behavior using Isolation Forest
- ThreatEngine: Unified threat detection engine
"""

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
from .threat_engine import ThreatEngine

__all__ = [
    # Models
    "ThreatLevel",
    "ThreatCategory",
    "DomainInfo",
    "TrafficFeatures",
    "ThreatAlert",
    "ThreatReport",
    # Components
    "DomainClassifier",
    "TrafficAnalyzer",
    "AnomalyDetector",
    "ThreatEngine",
]
