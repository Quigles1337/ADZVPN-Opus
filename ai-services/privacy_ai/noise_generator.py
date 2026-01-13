"""
Silver Noise Generator

Generates silver-seeded noise data for traffic obfuscation.

The noise is deterministically generated using silver ratio constants,
making it reproducible but appearing random to observers.

Created by: ADZ (Alexander David Zalewski) & Claude Opus 4.5
"""

import sys
import struct
import hashlib
from pathlib import Path
from typing import List, Optional, Tuple
from dataclasses import dataclass

# Add parent for silver constants
sys.path.insert(0, str(Path(__file__).parent.parent))
from silver_constants import (
    DELTA_S, TAU, ETA,
    pell, pell_sequence,
    SILVER_KDF_ITERATIONS,
)

from .models import NoisePacket


class SilverNoiseGenerator:
    """
    Silver-seeded noise generator.

    Generates deterministic but unpredictable-looking data
    using silver ratio mathematics.
    """

    # Silver-derived magic numbers
    SILVER_MAGIC = int(DELTA_S * 1_000_000_000)  # 2414213562
    TAU_MAGIC = int(TAU * 1_000_000_000)         # 1414213562
    ETA_MAGIC = int(ETA * 1_000_000_000)         # 707106781

    def __init__(self, seed: Optional[int] = None):
        """
        Initialize the noise generator.

        Args:
            seed: Optional seed for reproducibility
        """
        self.seed = seed or self.SILVER_MAGIC
        self._state = self.seed
        self._pell_cache = pell_sequence(30)
        self._packet_counter = 0

    def reset(self, seed: Optional[int] = None) -> None:
        """Reset the generator state."""
        self.seed = seed or self.SILVER_MAGIC
        self._state = self.seed
        self._packet_counter = 0

    def _silver_hash(self, data: bytes) -> bytes:
        """Hash data with silver-seeded mixing."""
        # Mix in silver constants
        mixed = data + struct.pack(">Q", self.SILVER_MAGIC)
        mixed = mixed + struct.pack(">Q", self.TAU_MAGIC)

        # Hash with iterations based on δ_S
        result = hashlib.sha256(mixed).digest()
        for _ in range(17):  # 17 is close to δ_S * 7
            result = hashlib.sha256(result + mixed[:8]).digest()

        return result

    def _advance_state(self) -> int:
        """Advance internal state using silver-ratio PRNG."""
        # Linear congruential generator with silver constants
        # state = (state * TAU_MAGIC + SILVER_MAGIC) mod 2^64
        self._state = (self._state * self.TAU_MAGIC + self.SILVER_MAGIC) & 0xFFFFFFFFFFFFFFFF
        return self._state

    def _pell_mix(self, value: int, index: int) -> int:
        """Mix value with Pell sequence."""
        pell_val = self._pell_cache[index % len(self._pell_cache)]
        return (value ^ (pell_val * self.ETA_MAGIC)) & 0xFFFFFFFF

    def generate_bytes(self, length: int) -> bytes:
        """
        Generate silver-seeded random bytes.

        Args:
            length: Number of bytes to generate

        Returns:
            Deterministic but random-looking bytes
        """
        result = bytearray()

        while len(result) < length:
            # Advance state
            state = self._advance_state()

            # Mix with Pell sequence
            mixed = self._pell_mix(state & 0xFFFFFFFF, len(result))

            # Convert to bytes
            result.extend(struct.pack(">I", mixed))

        return bytes(result[:length])

    def generate_packet(self, size: int) -> NoisePacket:
        """
        Generate a noise packet of specified size.

        Args:
            size: Packet size in bytes

        Returns:
            NoisePacket with silver-generated data
        """
        data = self.generate_bytes(size)
        seed = self._state

        self._packet_counter += 1

        return NoisePacket(
            data=data,
            size=size,
            seed=seed,
            pattern="silver",
        )

    def generate_padding(self, payload_size: int) -> bytes:
        """
        Generate padding to achieve silver ratio.

        Padding is sized so that:
        - Real payload is η² of total (≈50%)
        - Padding is λ² of total (≈50%)

        Args:
            payload_size: Size of real payload

        Returns:
            Padding bytes
        """
        # For balanced η² + λ² = 1, padding equals payload
        # ratio = λ²/η² = 0.5/0.5 = 1.0
        padding_size = payload_size

        return self.generate_bytes(padding_size)

    def generate_chaff_stream(
        self,
        count: int,
        min_size: int = 64,
        max_size: int = 1500,
    ) -> List[NoisePacket]:
        """
        Generate a stream of chaff packets.

        Packet sizes follow silver distribution.

        Args:
            count: Number of packets
            min_size: Minimum packet size
            max_size: Maximum packet size

        Returns:
            List of noise packets
        """
        packets = []
        size_range = max_size - min_size

        for i in range(count):
            # Size based on Pell sequence position
            pell_factor = self._pell_cache[i % len(self._pell_cache)]
            normalized = (pell_factor % 100) / 100.0

            # Apply silver scaling
            silver_scaled = normalized * TAU / DELTA_S
            size = min_size + int(silver_scaled * size_range)
            size = max(min_size, min(max_size, size))

            packets.append(self.generate_packet(size))

        return packets

    def verify_silver_distribution(self, data: bytes) -> float:
        """
        Verify how well data matches expected silver distribution.

        Returns score 0-1 where 1 is perfect silver distribution.
        """
        if len(data) < 16:
            return 0.0

        # Check byte distribution
        byte_counts = [0] * 256
        for b in data:
            byte_counts[b] += 1

        # Calculate chi-squared statistic
        expected = len(data) / 256
        chi_squared = sum(
            (count - expected) ** 2 / expected
            for count in byte_counts
            if expected > 0
        )

        # Convert to 0-1 score (lower chi-squared = better uniformity)
        # For uniform distribution, chi-squared ≈ 255 (degrees of freedom)
        uniformity_score = max(0, 1 - (chi_squared - 255) / 1000)

        return uniformity_score


class SilverChaffGenerator:
    """
    Specialized generator for chaff/decoy traffic.

    Creates realistic-looking traffic patterns that are
    indistinguishable from real traffic.
    """

    def __init__(self, noise_gen: Optional[SilverNoiseGenerator] = None):
        """Initialize chaff generator."""
        self.noise_gen = noise_gen or SilverNoiseGenerator()
        self._pattern_cache: List[int] = []
        self._build_pattern_cache()

    def _build_pattern_cache(self) -> None:
        """Build cache of packet size patterns."""
        # Common packet size patterns
        self._pattern_cache = [
            64,    # Minimum
            128,   # Small
            256,   # Medium-small
            512,   # Medium
            1024,  # Large
            1400,  # Near MTU
            1500,  # MTU
        ]

    def generate_realistic_size(self) -> int:
        """Generate a realistic packet size."""
        # Mix silver randomness with common patterns
        state = self.noise_gen._advance_state()

        # 70% chance of common size, 30% random
        if (state % 100) < 70:
            # Pick from common sizes with silver weighting
            index = (state // 100) % len(self._pattern_cache)
            return self._pattern_cache[index]
        else:
            # Random size with silver distribution
            return 64 + int((state % 1437) * TAU / DELTA_S)

    def generate_burst(
        self,
        packet_count: int,
    ) -> List[NoisePacket]:
        """
        Generate a burst of chaff packets.

        Simulates realistic traffic burst pattern.
        """
        packets = []

        for _ in range(packet_count):
            size = self.generate_realistic_size()
            packets.append(self.noise_gen.generate_packet(size))

        return packets

    def generate_session_chaff(
        self,
        duration_secs: float,
        packets_per_second: float = 10.0,
    ) -> List[Tuple[float, NoisePacket]]:
        """
        Generate chaff for an entire session.

        Returns list of (timestamp_offset, packet) tuples.
        """
        result = []
        total_packets = int(duration_secs * packets_per_second)
        avg_interval = 1.0 / packets_per_second

        current_time = 0.0

        for i in range(total_packets):
            # Silver-jittered interval
            pell_factor = pell(i % 20)
            jitter = (pell_factor % 100) / 100.0 * avg_interval * 0.5
            interval = avg_interval + jitter - avg_interval * 0.25

            current_time += max(0.01, interval)

            if current_time > duration_secs:
                break

            packet = self.noise_gen.generate_packet(self.generate_realistic_size())
            result.append((current_time, packet))

        return result
