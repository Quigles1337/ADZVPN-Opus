"""
Knowledge Base

Structured knowledge about SilverVPN, COINjecture, and silver ratio mathematics.

Created by: ADZ (Alexander David Zalewski) & Claude Opus 4.5
"""

import sys
from pathlib import Path
from enum import Enum
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

# Add parent for silver constants
sys.path.insert(0, str(Path(__file__).parent.parent))
from silver_constants import DELTA_S, TAU, ETA, ETA_SQUARED, LAMBDA_SQUARED, pell


class KnowledgeCategory(Enum):
    """Categories of knowledge."""
    VPN_BASICS = "vpn_basics"
    PRIVACY = "privacy"
    SECURITY = "security"
    SILVER_MATH = "silver_math"
    COINJECTURE = "coinjecture"
    TROUBLESHOOTING = "troubleshooting"
    CONFIGURATION = "configuration"


@dataclass
class KnowledgeEntry:
    """A single knowledge entry."""
    title: str
    content: str
    category: KnowledgeCategory
    keywords: List[str] = field(default_factory=list)
    related: List[str] = field(default_factory=list)  # Related entry titles

    def matches_query(self, query: str) -> float:
        """Score how well this entry matches a query (0-1)."""
        query_lower = query.lower()
        score = 0.0

        # Title match (highest weight)
        if query_lower in self.title.lower():
            score += 0.5

        # Keyword matches
        for keyword in self.keywords:
            if keyword.lower() in query_lower:
                score += 0.3
                break

        # Content match
        if query_lower in self.content.lower():
            score += 0.2

        return min(score, 1.0)


class KnowledgeBase:
    """
    Knowledge base for the assistant.

    Contains structured information about SilverVPN,
    silver ratio mathematics, and COINjecture.
    """

    def __init__(self):
        """Initialize the knowledge base."""
        self._entries: Dict[str, KnowledgeEntry] = {}
        self._load_default_knowledge()

    def _load_default_knowledge(self) -> None:
        """Load default knowledge entries."""
        # VPN Basics
        self.add_entry(KnowledgeEntry(
            title="What is SilverVPN?",
            content="""SilverVPN is a privacy-focused VPN built on silver ratio mathematics from the COINjecture blockchain project.

Key features:
- Silver ratio timing for anti-fingerprinting
- Balanced traffic shaping (η² + λ² = 1)
- AI-powered routing and threat detection
- Optional COINjecture P2P integration

The VPN uses the silver ratio (δ_S = 1 + √2 ≈ 2.414) throughout its protocol for elegant mathematical properties and enhanced privacy.""",
            category=KnowledgeCategory.VPN_BASICS,
            keywords=["silvervpn", "vpn", "what is", "about", "overview"],
        ))

        self.add_entry(KnowledgeEntry(
            title="Privacy Levels",
            content="""SilverVPN offers five privacy levels:

1. MINIMAL - Basic encryption only, no padding
2. STANDARD - Encryption + basic padding (default)
3. ENHANCED - Full traffic shaping with timing obfuscation
4. MAXIMUM - Constant bandwidth mode, all packets same size
5. PARANOID - Maximum + decoy traffic generation

Higher levels provide more privacy but use more bandwidth. The silver ratio (η² + λ² = 1) ensures balanced traffic where 50% is real data and 50% is padding.""",
            category=KnowledgeCategory.PRIVACY,
            keywords=["privacy", "level", "minimal", "standard", "enhanced", "maximum", "paranoid"],
            related=["Traffic Obfuscation", "Silver Ratio Balance"],
        ))

        self.add_entry(KnowledgeEntry(
            title="Traffic Obfuscation",
            content="""Traffic obfuscation hides your VPN usage patterns using silver ratio mathematics:

1. Size Padding - Packets padded to maintain η² + λ² = 1 ratio
2. Timing Obfuscation - Inter-packet delays follow Pell sequence
3. Constant Bandwidth - Optional mode that sends constant traffic
4. Decoy Traffic - Fake packets indistinguishable from real ones

The Pell sequence (0, 1, 2, 5, 12, 29, 70, 169...) converges to the silver ratio δ_S, creating timing patterns that are deterministic but appear random to observers.""",
            category=KnowledgeCategory.PRIVACY,
            keywords=["obfuscation", "traffic", "padding", "timing", "pell"],
            related=["Pell Sequence", "Silver Ratio Balance"],
        ))

        # Silver Math
        self.add_entry(KnowledgeEntry(
            title="Silver Ratio",
            content=f"""The silver ratio (δ_S) is the foundation of SilverVPN's mathematical design.

δ_S = 1 + √2 ≈ {DELTA_S:.10f}

Properties:
- Palindrome identity: δ_S = τ² + 1/δ_S
- Related to √2 (τ = √2 ≈ {TAU:.10f})
- η = 1/√2 ≈ {ETA:.10f} (unit component)

The silver ratio is used for:
- Key derivation (2414 iterations from δ_S × 1000)
- Load balancing weights
- Timing intervals
- Traffic shaping ratios""",
            category=KnowledgeCategory.SILVER_MATH,
            keywords=["silver ratio", "delta", "math", "√2", "tau", "eta"],
            related=["Pell Sequence", "Silver Ratio Balance"],
        ))

        self.add_entry(KnowledgeEntry(
            title="Pell Sequence",
            content=f"""The Pell sequence is a number sequence that converges to the silver ratio.

Definition: P(0)=0, P(1)=1, P(n)=2P(n-1)+P(n-2)

First 10 Pell numbers: {[pell(i) for i in range(10)]}

Property: lim(P(n+1)/P(n)) = δ_S as n → ∞

In SilverVPN, Pell numbers are used for:
- Timing intervals between packets
- Creating deterministic but non-obvious patterns
- Anti-fingerprinting (harder to detect than random or fixed timing)""",
            category=KnowledgeCategory.SILVER_MATH,
            keywords=["pell", "sequence", "numbers", "timing"],
            related=["Silver Ratio", "Traffic Obfuscation"],
        ))

        self.add_entry(KnowledgeEntry(
            title="Silver Ratio Balance",
            content=f"""The unit magnitude identity η² + λ² = 1 ensures balanced traffic.

- η² = {ETA_SQUARED} (real traffic portion)
- λ² = {LAMBDA_SQUARED} (padding portion)

This means in balanced mode:
- 50% of bandwidth is real data
- 50% of bandwidth is padding/noise

This makes traffic analysis extremely difficult because:
1. All packets appear the same size
2. Timing follows silver patterns
3. Real and fake traffic are indistinguishable""",
            category=KnowledgeCategory.SILVER_MATH,
            keywords=["balance", "eta", "lambda", "η²", "λ²", "unit", "magnitude"],
            related=["Traffic Obfuscation", "Privacy Levels"],
        ))

        # COINjecture
        self.add_entry(KnowledgeEntry(
            title="COINjecture Integration",
            content="""SilverVPN can optionally integrate with the COINjecture P2P network.

Features:
- P2P Discovery: Find VPN nodes via COINjecture's DHT
- Decentralized Exits: COINjecture nodes can serve as exit points
- Shared Math: Same silver ratio constants and key derivation
- Payments: Optional micropayments for bandwidth (future)

The integration shares the mathematical foundation, making both systems cryptographically compatible.""",
            category=KnowledgeCategory.COINJECTURE,
            keywords=["coinjecture", "p2p", "blockchain", "integration", "dht"],
        ))

        # Security
        self.add_entry(KnowledgeEntry(
            title="Threat Detection",
            content="""SilverVPN includes AI-powered threat detection:

1. Domain Classification
   - DGA (Domain Generation Algorithm) detection
   - Phishing pattern recognition
   - High-entropy domain flagging

2. Traffic Analysis
   - Data exfiltration detection
   - C2 beaconing patterns
   - Port scanning detection
   - DDoS traffic identification

3. Anomaly Detection
   - Isolation Forest algorithm
   - Behavioral heuristics
   - Silver-weighted scoring (δ_S, τ, 1.0 weights)

Threats are scored 0-1 and categorized by severity (LOW, MEDIUM, HIGH, CRITICAL).""",
            category=KnowledgeCategory.SECURITY,
            keywords=["threat", "security", "detection", "malware", "phishing", "anomaly"],
        ))

        # Troubleshooting
        self.add_entry(KnowledgeEntry(
            title="Connection Issues",
            content="""Common connection issues and solutions:

1. Cannot Connect
   - Check internet connection
   - Verify server is online (use /status command)
   - Try a different server
   - Check firewall settings

2. Slow Connection
   - Try a closer server (lower latency)
   - Reduce privacy level (less overhead)
   - Check for bandwidth throttling
   - The silver routing AI automatically selects optimal servers

3. Frequent Disconnects
   - Enable keep-alive packets
   - Check for network instability
   - Try UDP instead of TCP
   - Increase connection timeout

4. High Latency
   - Use silver routing to find faster paths
   - Reduce timing obfuscation level
   - Try servers with lower load""",
            category=KnowledgeCategory.TROUBLESHOOTING,
            keywords=["connection", "issue", "problem", "slow", "disconnect", "cannot connect"],
        ))

        # Configuration
        self.add_entry(KnowledgeEntry(
            title="Quick Start Guide",
            content="""Getting started with SilverVPN:

1. Install the client for your platform
2. Launch and create an account (or use anonymously)
3. The AI router will select the best server automatically
4. Click Connect

Default settings:
- Privacy Level: STANDARD (good balance)
- Routing: AI-optimized (silver-weighted)
- Protocol: UDP with QUIC fallback

Advanced users can:
- Choose specific servers manually
- Increase privacy level for sensitive activities
- Enable COINjecture integration
- Configure custom routing rules""",
            category=KnowledgeCategory.CONFIGURATION,
            keywords=["start", "setup", "configure", "install", "begin", "how to"],
        ))

        self.add_entry(KnowledgeEntry(
            title="Server Selection",
            content="""SilverVPN uses AI-powered silver routing for server selection.

The routing score uses silver-weighted factors:
- Latency: weight = δ_S (≈2.414) - highest priority
- Bandwidth: weight = τ (≈1.414) - medium priority
- Load: weight = 1.0 - base priority

Score formula:
score = (latency_score × δ_S + bandwidth_score × τ + load_score × 1.0) / (δ_S + τ + 1.0)

You can also manually select servers by:
- Region (US, EU, Asia, etc.)
- Features (P2P allowed, streaming optimized)
- Latency threshold
- Minimum bandwidth""",
            category=KnowledgeCategory.CONFIGURATION,
            keywords=["server", "select", "choose", "routing", "region"],
            related=["Silver Ratio"],
        ))

    def add_entry(self, entry: KnowledgeEntry) -> None:
        """Add a knowledge entry."""
        self._entries[entry.title] = entry

    def get_entry(self, title: str) -> Optional[KnowledgeEntry]:
        """Get an entry by title."""
        return self._entries.get(title)

    def search(self, query: str, max_results: int = 5) -> List[Tuple[KnowledgeEntry, float]]:
        """
        Search for relevant knowledge entries.

        Returns list of (entry, score) tuples sorted by relevance.
        """
        results = []

        for entry in self._entries.values():
            score = entry.matches_query(query)
            if score > 0:
                results.append((entry, score))

        # Sort by score descending
        results.sort(key=lambda x: x[1], reverse=True)

        return results[:max_results]

    def get_by_category(self, category: KnowledgeCategory) -> List[KnowledgeEntry]:
        """Get all entries in a category."""
        return [e for e in self._entries.values() if e.category == category]

    def get_context_for_query(self, query: str, max_entries: int = 3) -> str:
        """
        Get relevant knowledge as context for a query.

        Returns formatted string to include in the prompt.
        """
        results = self.search(query, max_results=max_entries)

        if not results:
            return ""

        context_parts = ["Relevant knowledge:"]
        for entry, score in results:
            if score >= 0.2:  # Only include reasonably relevant entries
                context_parts.append(f"\n## {entry.title}\n{entry.content}")

        return "\n".join(context_parts)

    def list_topics(self) -> List[str]:
        """List all available topics."""
        return list(self._entries.keys())

    @property
    def entry_count(self) -> int:
        """Get number of knowledge entries."""
        return len(self._entries)
