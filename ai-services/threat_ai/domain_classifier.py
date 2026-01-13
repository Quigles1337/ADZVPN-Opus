"""
Domain Classifier

Classifies domains as safe, suspicious, or malicious.

Uses multiple signals:
- Domain features (length, entropy, structure)
- Known bad/good lists
- Pattern matching for DGA (Domain Generation Algorithm) detection
- TLD reputation

Created by: ADZ (Alexander David Zalewski) & Claude Opus 4.5
"""

import math
import re
import string
from typing import Dict, List, Optional, Set, Tuple
from collections import Counter

from .models import DomainInfo, ThreatLevel, ThreatCategory


class DomainClassifier:
    """
    Domain threat classifier.

    Uses heuristics and pattern matching to classify domains.
    In production, this would use a trained ML model (e.g., BERT).
    """

    # Known malicious TLDs (high-risk)
    HIGH_RISK_TLDS: Set[str] = {
        "xyz", "top", "club", "work", "date", "racing", "win",
        "bid", "stream", "download", "gq", "cf", "tk", "ml", "ga",
    }

    # Known safe TLDs
    SAFE_TLDS: Set[str] = {
        "com", "org", "net", "edu", "gov", "mil",
    }

    # Suspicious patterns
    SUSPICIOUS_PATTERNS: List[Tuple[str, ThreatCategory, float]] = [
        (r"login|signin|account|secure|verify|update|confirm", ThreatCategory.PHISHING, 0.3),
        (r"paypal|apple|microsoft|google|amazon|netflix|bank", ThreatCategory.PHISHING, 0.4),
        (r"[0-9]{8,}", ThreatCategory.BOTNET, 0.5),  # Long number sequences
        (r"[a-z]{20,}", ThreatCategory.BOTNET, 0.4),  # Very long random strings
        (r"(\.ru|\.cn|\.tk)\.", ThreatCategory.SUSPICIOUS, 0.2),  # Suspicious country TLDs
        (r"free.*download|download.*free", ThreatCategory.MALWARE, 0.3),
        (r"crack|keygen|warez|torrent", ThreatCategory.MALWARE, 0.5),
        (r"bitcoin|crypto|wallet|mining", ThreatCategory.CRYPTO_MINING, 0.2),
    ]

    # Known bad domains (sample - in production, use threat intelligence feeds)
    KNOWN_BAD_DOMAINS: Set[str] = {
        "malware.com", "phishing.net", "evil.xyz",
        "bad-actor.top", "steal-data.club",
    }

    # Known good domains (sample)
    KNOWN_GOOD_DOMAINS: Set[str] = {
        "google.com", "microsoft.com", "apple.com", "amazon.com",
        "github.com", "cloudflare.com", "aws.amazon.com",
        "anthropic.com", "openai.com",
    }

    def __init__(
        self,
        entropy_threshold: float = 3.5,
        length_threshold: int = 50,
        suspicious_score_threshold: float = 0.5,
    ):
        """
        Initialize the domain classifier.

        Args:
            entropy_threshold: Entropy above this is suspicious
            length_threshold: Domain length above this is suspicious
            suspicious_score_threshold: Score above this triggers alert
        """
        self.entropy_threshold = entropy_threshold
        self.length_threshold = length_threshold
        self.suspicious_score_threshold = suspicious_score_threshold

        # Compile patterns
        self._compiled_patterns = [
            (re.compile(pattern, re.IGNORECASE), category, score)
            for pattern, category, score in self.SUSPICIOUS_PATTERNS
        ]

    def calculate_entropy(self, text: str) -> float:
        """
        Calculate Shannon entropy of a string.

        High entropy suggests random/generated domain (DGA).
        """
        if not text:
            return 0.0

        # Count character frequencies
        freq = Counter(text.lower())
        length = len(text)

        # Calculate entropy
        entropy = 0.0
        for count in freq.values():
            if count > 0:
                prob = count / length
                entropy -= prob * math.log2(prob)

        return entropy

    def extract_features(self, domain: str) -> DomainInfo:
        """Extract features from a domain."""
        info = DomainInfo(domain=domain)

        # Clean domain
        domain_clean = domain.lower().strip()
        if domain_clean.startswith("http://"):
            domain_clean = domain_clean[7:]
        if domain_clean.startswith("https://"):
            domain_clean = domain_clean[8:]
        if domain_clean.startswith("www."):
            domain_clean = domain_clean[4:]
        domain_clean = domain_clean.split("/")[0]  # Remove path

        # Basic features
        info.length = len(domain_clean)
        info.entropy = self.calculate_entropy(domain_clean.replace(".", ""))

        # Check if it's an IP address
        ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
        info.has_ip = bool(re.match(ip_pattern, domain_clean))

        # Count subdomains
        parts = domain_clean.split(".")
        info.subdomain_count = max(0, len(parts) - 2)

        # Extract TLD
        if len(parts) >= 2:
            info.tld = parts[-1]

        return info

    def check_known_lists(self, domain: str, info: DomainInfo) -> None:
        """Check domain against known good/bad lists."""
        domain_lower = domain.lower()

        # Check exact match
        if domain_lower in self.KNOWN_BAD_DOMAINS:
            info.is_known_bad = True
            info.reputation_score = 0.0
            return

        if domain_lower in self.KNOWN_GOOD_DOMAINS:
            info.is_known_good = True
            info.reputation_score = 1.0
            return

        # Check if it's a subdomain of known domains
        for bad in self.KNOWN_BAD_DOMAINS:
            if domain_lower.endswith("." + bad):
                info.is_known_bad = True
                info.reputation_score = 0.1
                return

        for good in self.KNOWN_GOOD_DOMAINS:
            if domain_lower.endswith("." + good):
                info.is_known_good = True
                info.reputation_score = 0.9
                return

    def calculate_threat_score(self, info: DomainInfo) -> Tuple[float, ThreatCategory]:
        """
        Calculate threat score based on features.

        Returns (score, category) where score is 0-1.
        """
        score = 0.0
        category = ThreatCategory.NONE
        domain = info.domain.lower()

        # Known bad/good
        if info.is_known_bad:
            return 1.0, ThreatCategory.MALWARE
        if info.is_known_good:
            return 0.0, ThreatCategory.NONE

        # IP address in domain
        if info.has_ip:
            score += 0.3
            category = ThreatCategory.SUSPICIOUS

        # High entropy (possible DGA)
        if info.entropy > self.entropy_threshold:
            entropy_score = min((info.entropy - self.entropy_threshold) / 2.0, 0.5)
            score += entropy_score
            if entropy_score > 0.3:
                category = ThreatCategory.BOTNET

        # Long domain
        if info.length > self.length_threshold:
            length_score = min((info.length - self.length_threshold) / 50.0, 0.3)
            score += length_score

        # Many subdomains
        if info.subdomain_count > 3:
            score += 0.1 * (info.subdomain_count - 3)
            if score > 0.2:
                category = ThreatCategory.PHISHING

        # High-risk TLD
        if info.tld in self.HIGH_RISK_TLDS:
            score += 0.2

        # Safe TLD bonus (reduce score)
        if info.tld in self.SAFE_TLDS:
            score = max(0, score - 0.1)

        # Pattern matching
        for pattern, pat_category, pat_score in self._compiled_patterns:
            if pattern.search(domain):
                score += pat_score
                if pat_score > 0.3:
                    category = pat_category

        # Cap score at 1.0
        score = min(score, 1.0)

        return score, category

    def classify(self, domain: str) -> DomainInfo:
        """
        Classify a domain.

        Returns DomainInfo with threat assessment.
        """
        # Extract features
        info = self.extract_features(domain)

        # Check known lists
        self.check_known_lists(domain, info)

        # Calculate threat score
        score, category = self.calculate_threat_score(info)

        # Set results
        info.confidence = min(0.5 + score, 1.0)  # Higher score = higher confidence
        info.threat_level = ThreatLevel.from_score(score)
        info.threat_category = category
        info.reputation_score = 1.0 - score

        return info

    def classify_batch(self, domains: List[str]) -> List[DomainInfo]:
        """Classify multiple domains."""
        return [self.classify(d) for d in domains]

    def is_suspicious(self, domain: str) -> bool:
        """Quick check if domain is suspicious."""
        info = self.classify(domain)
        return info.threat_level.to_score() >= self.suspicious_score_threshold

    def get_threat_level(self, domain: str) -> ThreatLevel:
        """Get threat level for a domain."""
        return self.classify(domain).threat_level


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def is_valid_domain(domain: str) -> bool:
    """Check if string is a valid domain format."""
    if not domain or len(domain) > 253:
        return False

    # Basic domain pattern
    pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
    return bool(re.match(pattern, domain))


def extract_domain_from_url(url: str) -> Optional[str]:
    """Extract domain from URL."""
    # Remove protocol
    if "://" in url:
        url = url.split("://", 1)[1]

    # Remove path
    url = url.split("/")[0]

    # Remove port
    url = url.split(":")[0]

    # Remove www
    if url.startswith("www."):
        url = url[4:]

    return url if is_valid_domain(url) else None
