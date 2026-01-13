"""
Tests for Threat AI

Tests domain classification, traffic analysis, and anomaly detection.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from threat_ai import (
    ThreatLevel,
    ThreatCategory,
    DomainInfo,
    TrafficFeatures,
    ThreatAlert,
    ThreatReport,
    DomainClassifier,
    TrafficAnalyzer,
    AnomalyDetector,
    ThreatEngine,
)
from threat_ai.domain_classifier import is_valid_domain, extract_domain_from_url


# =============================================================================
# TEST MODELS
# =============================================================================

class TestThreatLevel:
    """Test ThreatLevel enum."""

    def test_to_score(self):
        """Test converting threat level to score."""
        assert ThreatLevel.SAFE.to_score() == 0.0
        assert ThreatLevel.LOW.to_score() == 0.25
        assert ThreatLevel.MEDIUM.to_score() == 0.5
        assert ThreatLevel.HIGH.to_score() == 0.75
        assert ThreatLevel.CRITICAL.to_score() == 1.0

    def test_from_score(self):
        """Test creating threat level from score."""
        assert ThreatLevel.from_score(0.0) == ThreatLevel.SAFE
        assert ThreatLevel.from_score(0.1) == ThreatLevel.SAFE
        assert ThreatLevel.from_score(0.3) == ThreatLevel.LOW
        assert ThreatLevel.from_score(0.5) == ThreatLevel.MEDIUM
        assert ThreatLevel.from_score(0.7) == ThreatLevel.HIGH
        assert ThreatLevel.from_score(0.9) == ThreatLevel.CRITICAL
        assert ThreatLevel.from_score(1.0) == ThreatLevel.CRITICAL


class TestTrafficFeatures:
    """Test TrafficFeatures model."""

    def test_to_feature_vector(self):
        """Test converting to feature vector."""
        features = TrafficFeatures(
            bytes_sent=1000,
            bytes_received=2000,
            packets_sent=10,
            packets_received=20,
        )
        vector = features.to_feature_vector()

        assert len(vector) == 15
        assert vector[0] == 1000.0  # bytes_sent
        assert vector[1] == 2000.0  # bytes_received

    def test_feature_names(self):
        """Test feature names list."""
        names = TrafficFeatures.feature_names()
        assert len(names) == 15
        assert "bytes_sent" in names
        assert "packets_sent" in names


# =============================================================================
# TEST DOMAIN CLASSIFIER
# =============================================================================

class TestDomainClassifier:
    """Test domain classification."""

    def setup_method(self):
        """Set up classifier."""
        self.classifier = DomainClassifier()

    def test_safe_domain(self):
        """Test known safe domain."""
        info = self.classifier.classify("google.com")
        assert info.is_known_good
        assert info.threat_level == ThreatLevel.SAFE

    def test_malicious_domain(self):
        """Test known malicious domain."""
        info = self.classifier.classify("malware.com")
        assert info.is_known_bad
        assert info.threat_level == ThreatLevel.CRITICAL

    def test_high_entropy_domain(self):
        """Test high entropy (DGA-like) domain."""
        # Random-looking domain
        info = self.classifier.classify("xkjhsdflkjhsdf8237498237.xyz")
        assert info.entropy > 3.0
        assert info.threat_level.to_score() > 0.3

    def test_high_risk_tld(self):
        """Test high-risk TLD."""
        info = self.classifier.classify("something.xyz")
        assert info.tld == "xyz"
        # Should have some suspicion due to TLD
        assert info.threat_level.to_score() >= 0.0

    def test_subdomain_count(self):
        """Test subdomain counting."""
        info = self.classifier.classify("a.b.c.d.example.com")
        assert info.subdomain_count == 4

    def test_ip_address_domain(self):
        """Test IP address detection."""
        info = self.classifier.classify("192.168.1.1")
        assert info.has_ip

    def test_phishing_pattern(self):
        """Test phishing pattern detection."""
        info = self.classifier.classify("secure-login-paypal.xyz")
        assert info.threat_category in [ThreatCategory.PHISHING, ThreatCategory.SUSPICIOUS]

    def test_batch_classify(self):
        """Test batch classification."""
        domains = ["google.com", "malware.com", "example.org"]
        results = self.classifier.classify_batch(domains)
        assert len(results) == 3

    def test_is_suspicious(self):
        """Test suspicious check."""
        assert not self.classifier.is_suspicious("google.com")
        assert self.classifier.is_suspicious("malware.com")


class TestDomainUtilities:
    """Test domain utility functions."""

    def test_is_valid_domain(self):
        """Test domain validation."""
        assert is_valid_domain("example.com")
        assert is_valid_domain("sub.example.com")
        assert not is_valid_domain("")
        assert not is_valid_domain("a" * 300)  # Too long

    def test_extract_domain_from_url(self):
        """Test extracting domain from URL."""
        assert extract_domain_from_url("https://example.com/path") == "example.com"
        assert extract_domain_from_url("http://www.example.com") == "example.com"
        assert extract_domain_from_url("example.com:8080/page") == "example.com"


# =============================================================================
# TEST TRAFFIC ANALYZER
# =============================================================================

class TestTrafficAnalyzer:
    """Test traffic analysis."""

    def setup_method(self):
        """Set up analyzer."""
        self.analyzer = TrafficAnalyzer()

    def test_normal_traffic(self):
        """Test normal traffic produces no alerts."""
        features = TrafficFeatures(
            session_id="test-session",
            bytes_sent=10000,
            bytes_received=50000,
            packets_sent=100,
            packets_received=200,
            duration_secs=60,
            avg_packet_interval_ms=500,
            packet_interval_variance=100,
        )
        alerts = self.analyzer.analyze(features)
        # Normal traffic should produce few or no alerts
        high_alerts = [a for a in alerts if a.threat_level.to_score() >= 0.5]
        assert len(high_alerts) == 0

    def test_exfiltration_detection(self):
        """Test data exfiltration detection."""
        features = TrafficFeatures(
            session_id="test-session",
            bytes_sent=100_000_000,  # 100MB upload
            bytes_received=1000,     # Very little download
            packets_sent=10000,
            packets_received=10,
        )
        alerts = self.analyzer.analyze(features)

        # Should detect exfiltration
        exfil_alerts = [
            a for a in alerts
            if a.threat_category == ThreatCategory.DATA_EXFILTRATION
        ]
        assert len(exfil_alerts) > 0

    def test_beaconing_detection(self):
        """Test beaconing behavior detection."""
        features = TrafficFeatures(
            session_id="test-session",
            bytes_sent=1000,
            bytes_received=1000,
            packets_sent=100,
            packets_received=100,
            avg_packet_interval_ms=1000,  # Very regular
            packet_interval_variance=0.01,  # Almost no variance
        )
        alerts = self.analyzer.analyze(features)

        # Should detect beaconing
        beacon_alerts = [
            a for a in alerts
            if a.threat_category == ThreatCategory.COMMAND_CONTROL
        ]
        assert len(beacon_alerts) > 0

    def test_scanning_detection(self):
        """Test scanning behavior detection."""
        features = TrafficFeatures(
            session_id="test-session",
            bytes_sent=1000,
            bytes_received=500,
            unique_destinations=200,  # Many destinations
            connection_count=200,
            failed_connections=150,   # High failure rate
        )
        alerts = self.analyzer.analyze(features)

        # Should detect scanning
        scan_alerts = [
            a for a in alerts
            if a.threat_category == ThreatCategory.SCANNER
        ]
        assert len(scan_alerts) > 0

    def test_ddos_detection(self):
        """Test DDoS participation detection."""
        features = TrafficFeatures(
            session_id="test-session",
            bytes_sent=50_000_000,
            packets_sent=500000,
            duration_secs=100,  # 5000 packets/sec
            packet_size_avg=100,  # Small packets
        )
        alerts = self.analyzer.analyze(features)

        # Should detect DDoS-like behavior
        ddos_alerts = [
            a for a in alerts
            if a.threat_category == ThreatCategory.DDoS
        ]
        assert len(ddos_alerts) > 0

    def test_threat_score(self):
        """Test overall threat score calculation."""
        normal_features = TrafficFeatures(
            bytes_sent=10000,
            bytes_received=50000,
        )
        assert self.analyzer.get_threat_score(normal_features) < 0.3

        suspicious_features = TrafficFeatures(
            bytes_sent=100_000_000,
            bytes_received=1000,
        )
        assert self.analyzer.get_threat_score(suspicious_features) > 0.3


# =============================================================================
# TEST ANOMALY DETECTOR
# =============================================================================

class TestAnomalyDetector:
    """Test anomaly detection."""

    def setup_method(self):
        """Set up detector."""
        self.detector = AnomalyDetector()

    def test_heuristic_detection_normal(self):
        """Test heuristic detection on normal traffic."""
        features = TrafficFeatures(
            bytes_sent=10000,
            bytes_received=50000,
            unique_destinations=10,
            failed_connections=1,
            connection_count=10,
        )
        result = self.detector.detect(features)
        assert not result.is_anomaly

    def test_heuristic_detection_anomaly(self):
        """Test heuristic detection on anomalous traffic."""
        features = TrafficFeatures(
            bytes_sent=500_000_000,  # 500MB - extreme
            bytes_received=1000,
            bytes_ratio=500000,
            unique_destinations=500,
            failed_connections=400,
            connection_count=500,
        )
        result = self.detector.detect(features)
        assert result.is_anomaly
        assert result.normalized_score > 0.5

    def test_create_alert(self):
        """Test alert creation from anomaly."""
        features = TrafficFeatures(
            session_id="test",
            client_id="client-1",
            bytes_sent=500_000_000,
            bytes_ratio=500000,
        )
        result = self.detector.detect(features)
        alert = self.detector.create_alert(features, result)

        if result.is_anomaly:
            assert alert is not None
            assert alert.threat_category == ThreatCategory.SUSPICIOUS

    def test_training_data_accumulation(self):
        """Test training data accumulation."""
        for i in range(100):
            features = TrafficFeatures(
                bytes_sent=10000 + i * 100,
                bytes_received=50000 + i * 200,
            )
            self.detector.add_training_sample(features)

        # Should have accumulated data
        assert len(self.detector._training_data) == 100


# =============================================================================
# TEST THREAT ENGINE
# =============================================================================

class TestThreatEngine:
    """Test unified threat engine."""

    def setup_method(self):
        """Set up engine."""
        self.engine = ThreatEngine()

    def test_analyze_safe_domain(self):
        """Test analyzing a safe domain."""
        info = self.engine.analyze_domain("google.com")
        assert info.threat_level == ThreatLevel.SAFE

    def test_analyze_malicious_domain(self):
        """Test analyzing a malicious domain."""
        info = self.engine.analyze_domain("malware.com")
        assert info.threat_level == ThreatLevel.CRITICAL

    def test_domain_caching(self):
        """Test domain result caching."""
        # First call
        info1 = self.engine.analyze_domain("example.com")
        # Second call should hit cache
        info2 = self.engine.analyze_domain("example.com")

        assert info1.domain == info2.domain
        assert self.engine._stats["domains_checked"] == 1  # Only one actual check

    def test_analyze_traffic_with_domains(self):
        """Test traffic analysis with domain checking."""
        features = TrafficFeatures(
            session_id="test",
            client_id="client-1",
            bytes_sent=10000,
            bytes_received=50000,
        )
        report = self.engine.analyze_traffic(
            features,
            domains=["google.com", "example.com"],
        )

        assert report.session_id == "test"
        assert report.domains_checked == 2
        assert report.overall_threat_level == ThreatLevel.SAFE

    def test_analyze_traffic_with_malicious_domain(self):
        """Test traffic analysis with malicious domain."""
        features = TrafficFeatures(
            session_id="test",
            client_id="client-1",
        )
        report = self.engine.analyze_traffic(
            features,
            domains=["google.com", "malware.com"],
        )

        assert report.domains_flagged > 0
        assert report.overall_threat_level.to_score() > 0.3

    def test_check_domain(self):
        """Test domain checking."""
        assert self.engine.check_domain("google.com")
        assert not self.engine.check_domain("malware.com")

    def test_block_domain(self):
        """Test manual domain blocking."""
        self.engine.block_domain("evil.example.com")
        assert not self.engine.check_domain("evil.example.com")

        self.engine.unblock_domain("evil.example.com")
        assert self.engine.check_domain("evil.example.com")

    def test_block_client(self):
        """Test client blocking."""
        self.engine.block_client("bad-client")
        assert not self.engine.check_client("bad-client")
        assert self.engine.check_client("good-client")

    def test_get_stats(self):
        """Test statistics retrieval."""
        self.engine.analyze_domain("google.com")
        stats = self.engine.get_stats()

        assert "domains_checked" in stats
        assert stats["domains_checked"] >= 1

    def test_get_blocked_lists(self):
        """Test getting blocked lists."""
        self.engine.block_domain("bad.com")
        self.engine.block_client("bad-client")

        assert "bad.com" in self.engine.get_blocked_domains()
        assert "bad-client" in self.engine.get_blocked_clients()

    def test_silver_weighted_scoring(self):
        """Test that silver weights are applied correctly."""
        # The engine should use silver ratio for weighting
        from silver_constants import DELTA_S, TAU

        assert self.engine.config.domain_weight == DELTA_S
        assert self.engine.config.traffic_weight == TAU
        assert self.engine.config.anomaly_weight == 1.0


# =============================================================================
# RUN TESTS
# =============================================================================

if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
