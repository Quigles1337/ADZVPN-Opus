"""
Traffic Analyzer

Analyzes VPN traffic patterns for threat detection.

Privacy-preserving: Only analyzes metadata, never packet contents.

Detects:
- Data exfiltration (unusual upload patterns)
- Beaconing (regular interval communications)
- Scanning behavior (many failed connections)
- DDoS participation (high volume attacks)

Created by: ADZ (Alexander David Zalewski) & Claude Opus 4.5
"""

import sys
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
import math

# Add parent for silver constants
sys.path.insert(0, str(Path(__file__).parent.parent))
from silver_constants import DELTA_S, TAU

from .models import (
    TrafficFeatures,
    ThreatLevel,
    ThreatCategory,
    ThreatAlert,
)


@dataclass
class TrafficProfile:
    """Statistical profile of normal traffic."""
    # Volume baselines
    avg_bytes_per_session: float = 1_000_000  # 1 MB
    avg_packets_per_session: float = 1000
    max_bytes_ratio: float = 10.0  # Max send/receive ratio

    # Timing baselines
    avg_session_duration: float = 300.0  # 5 minutes
    min_packet_interval_ms: float = 1.0  # Minimum normal interval
    max_packet_interval_variance: float = 10000.0

    # Connection baselines
    max_destinations_per_hour: int = 100
    max_failed_connection_rate: float = 0.2  # 20%

    # Thresholds (silver-scaled)
    exfiltration_threshold: float = 5.0  # Times normal upload
    beaconing_variance_threshold: float = 0.1  # Very regular = suspicious
    scanning_threshold: int = 50  # Destinations in short time


class TrafficAnalyzer:
    """
    Traffic pattern analyzer.

    Uses statistical analysis to detect anomalous patterns
    that may indicate threats.
    """

    def __init__(self, profile: Optional[TrafficProfile] = None):
        """
        Initialize the analyzer.

        Args:
            profile: Traffic profile to compare against
        """
        self.profile = profile or TrafficProfile()

        # Historical data for baseline calculation
        self._session_history: List[TrafficFeatures] = []
        self._max_history = 1000

    def analyze(self, features: TrafficFeatures) -> List[ThreatAlert]:
        """
        Analyze traffic features for threats.

        Returns list of detected threats.
        """
        alerts: List[ThreatAlert] = []

        # Check for data exfiltration
        exfil_alert = self._check_exfiltration(features)
        if exfil_alert:
            alerts.append(exfil_alert)

        # Check for beaconing behavior
        beacon_alert = self._check_beaconing(features)
        if beacon_alert:
            alerts.append(beacon_alert)

        # Check for scanning behavior
        scan_alert = self._check_scanning(features)
        if scan_alert:
            alerts.append(scan_alert)

        # Check for DDoS participation
        ddos_alert = self._check_ddos(features)
        if ddos_alert:
            alerts.append(ddos_alert)

        # Check for unusual timing
        timing_alert = self._check_unusual_timing(features)
        if timing_alert:
            alerts.append(timing_alert)

        # Record in history
        self._record_session(features)

        return alerts

    def _check_exfiltration(self, features: TrafficFeatures) -> Optional[ThreatAlert]:
        """
        Check for data exfiltration patterns.

        Signs:
        - High upload/download ratio (sending more than receiving)
        - Large volume uploads
        - Uploads to unusual destinations
        """
        # Calculate upload ratio
        if features.bytes_received > 0:
            upload_ratio = features.bytes_sent / features.bytes_received
        else:
            upload_ratio = features.bytes_sent / 1000.0  # Avoid div by zero

        # Check if significantly higher than normal
        if upload_ratio > self.profile.exfiltration_threshold:
            # Calculate threat score (silver-scaled)
            excess_ratio = upload_ratio / self.profile.exfiltration_threshold
            score = min(excess_ratio / DELTA_S, 1.0)

            return ThreatAlert(
                threat_level=ThreatLevel.from_score(score),
                threat_category=ThreatCategory.DATA_EXFILTRATION,
                confidence=min(0.5 + score * 0.5, 0.95),
                source="traffic_analyzer:exfiltration",
                session_id=features.session_id,
                client_id=features.client_id,
                description=f"Unusual upload pattern detected: {upload_ratio:.1f}x more data sent than received",
                indicators=[
                    f"Upload ratio: {upload_ratio:.2f}",
                    f"Bytes sent: {features.bytes_sent}",
                    f"Bytes received: {features.bytes_received}",
                ],
                recommendations=[
                    "Review destination addresses",
                    "Check for unauthorized data transfers",
                    "Verify client application behavior",
                ],
            )

        return None

    def _check_beaconing(self, features: TrafficFeatures) -> Optional[ThreatAlert]:
        """
        Check for beaconing behavior (C2 communication).

        Signs:
        - Very regular packet intervals (low variance)
        - Consistent communication patterns
        - Small, regular packets
        """
        # Beaconing has very low interval variance
        if features.packet_interval_variance < self.profile.beaconing_variance_threshold:
            # Check if enough packets to be meaningful
            if features.packets_sent < 10:
                return None

            # Calculate threat score
            variance_ratio = features.packet_interval_variance / self.profile.beaconing_variance_threshold
            score = min((1.0 - variance_ratio) * TAU, 1.0)

            if score < 0.3:
                return None

            return ThreatAlert(
                threat_level=ThreatLevel.from_score(score),
                threat_category=ThreatCategory.COMMAND_CONTROL,
                confidence=min(0.4 + score * 0.4, 0.85),
                source="traffic_analyzer:beaconing",
                session_id=features.session_id,
                client_id=features.client_id,
                description="Beaconing behavior detected: suspiciously regular communication pattern",
                indicators=[
                    f"Packet interval variance: {features.packet_interval_variance:.4f}",
                    f"Average interval: {features.avg_packet_interval_ms:.2f}ms",
                    f"Packets sent: {features.packets_sent}",
                ],
                recommendations=[
                    "Investigate destination for C2 indicators",
                    "Check for malware on client device",
                    "Review process activity on client",
                ],
            )

        return None

    def _check_scanning(self, features: TrafficFeatures) -> Optional[ThreatAlert]:
        """
        Check for port/network scanning behavior.

        Signs:
        - Many unique destinations
        - High connection failure rate
        - Short connections
        """
        # Many destinations with high failure rate
        if features.unique_destinations > self.profile.scanning_threshold:
            # Calculate failure rate
            total_connections = features.connection_count
            if total_connections > 0:
                failure_rate = features.failed_connections / total_connections
            else:
                failure_rate = 0

            if failure_rate > self.profile.max_failed_connection_rate:
                score = min(
                    (features.unique_destinations / self.profile.scanning_threshold - 1) * 0.5 +
                    failure_rate * 0.5,
                    1.0
                )

                return ThreatAlert(
                    threat_level=ThreatLevel.from_score(score),
                    threat_category=ThreatCategory.SCANNER,
                    confidence=min(0.6 + score * 0.3, 0.9),
                    source="traffic_analyzer:scanning",
                    session_id=features.session_id,
                    client_id=features.client_id,
                    description="Network scanning behavior detected",
                    indicators=[
                        f"Unique destinations: {features.unique_destinations}",
                        f"Failed connections: {features.failed_connections}",
                        f"Failure rate: {failure_rate:.1%}",
                    ],
                    recommendations=[
                        "Block or rate-limit client",
                        "Review client for compromise",
                        "Check for port scanning tools",
                    ],
                )

        return None

    def _check_ddos(self, features: TrafficFeatures) -> Optional[ThreatAlert]:
        """
        Check for DDoS participation.

        Signs:
        - Very high packet rate
        - High bandwidth usage
        - Many small packets to few destinations
        """
        # Calculate packet rate
        if features.duration_secs > 0:
            packet_rate = features.packets_sent / features.duration_secs
        else:
            return None

        # High packet rate with small packets
        if features.packet_size_avg > 0:
            is_small_packets = features.packet_size_avg < 200  # Small packets
        else:
            is_small_packets = False

        # Threshold: 1000 packets/sec with small packets
        if packet_rate > 1000 and is_small_packets:
            score = min(packet_rate / 5000, 1.0)

            return ThreatAlert(
                threat_level=ThreatLevel.from_score(score),
                threat_category=ThreatCategory.DDoS,
                confidence=min(0.5 + score * 0.4, 0.9),
                source="traffic_analyzer:ddos",
                session_id=features.session_id,
                client_id=features.client_id,
                description="Possible DDoS participation detected",
                indicators=[
                    f"Packet rate: {packet_rate:.0f}/sec",
                    f"Average packet size: {features.packet_size_avg:.0f} bytes",
                    f"Duration: {features.duration_secs:.1f}s",
                ],
                recommendations=[
                    "Rate limit client immediately",
                    "Block if behavior continues",
                    "Check client for botnet infection",
                ],
            )

        return None

    def _check_unusual_timing(self, features: TrafficFeatures) -> Optional[ThreatAlert]:
        """
        Check for unusual timing patterns.

        Signs:
        - Activity at unusual hours
        - Very long sessions
        - Suspicious time patterns
        """
        # Weekend + late night (0-5 AM) with high activity
        is_suspicious_time = (
            features.is_weekend and
            features.hour_of_day >= 0 and
            features.hour_of_day <= 5
        )

        # Long duration session with activity
        is_long_session = features.duration_secs > 3600 * 8  # 8+ hours

        if is_suspicious_time and features.bytes_sent > 10_000_000:  # 10MB+
            return ThreatAlert(
                threat_level=ThreatLevel.LOW,
                threat_category=ThreatCategory.SUSPICIOUS,
                confidence=0.5,
                source="traffic_analyzer:timing",
                session_id=features.session_id,
                client_id=features.client_id,
                description="Unusual activity timing detected",
                indicators=[
                    f"Hour: {features.hour_of_day}",
                    f"Weekend: {features.is_weekend}",
                    f"Data transferred: {features.bytes_sent / 1_000_000:.1f} MB",
                ],
                recommendations=[
                    "Verify user identity",
                    "Check if activity is expected",
                ],
            )

        return None

    def _record_session(self, features: TrafficFeatures) -> None:
        """Record session in history for baseline calculation."""
        self._session_history.append(features)

        # Trim history
        if len(self._session_history) > self._max_history:
            self._session_history = self._session_history[-self._max_history:]

    def calculate_baseline(self) -> TrafficProfile:
        """Calculate baseline profile from history."""
        if len(self._session_history) < 10:
            return self.profile

        # Calculate averages
        total_bytes = sum(f.bytes_sent + f.bytes_received for f in self._session_history)
        total_packets = sum(f.packets_sent + f.packets_received for f in self._session_history)
        total_duration = sum(f.duration_secs for f in self._session_history)

        n = len(self._session_history)

        return TrafficProfile(
            avg_bytes_per_session=total_bytes / n,
            avg_packets_per_session=total_packets / n,
            avg_session_duration=total_duration / n,
        )

    def get_threat_score(self, features: TrafficFeatures) -> float:
        """
        Get overall threat score for traffic.

        Returns score 0-1 where higher = more threatening.
        """
        alerts = self.analyze(features)

        if not alerts:
            return 0.0

        # Combine scores (max with boost for multiple alerts)
        scores = [a.threat_level.to_score() for a in alerts]
        max_score = max(scores)
        alert_boost = min(len(alerts) * 0.1, 0.3)

        return min(max_score + alert_boost, 1.0)
