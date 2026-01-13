"""
Traffic Obfuscator

Obfuscates VPN traffic to resist traffic analysis.

Uses silver ratio mathematics for:
- Packet padding (η² + λ² = 1 balance)
- Size normalization
- Pattern hiding

Created by: ADZ (Alexander David Zalewski) & Claude Opus 4.5
"""

import sys
from pathlib import Path
from typing import List, Optional, Tuple
from dataclasses import dataclass

# Add parent for silver constants
sys.path.insert(0, str(Path(__file__).parent.parent))
from silver_constants import (
    DELTA_S, TAU, ETA,
    ETA_SQUARED, LAMBDA_SQUARED,
    silver_padding,
)

from .models import (
    ObfuscationConfig,
    ObfuscationResult,
    TrafficProfile,
    PrivacyLevel,
)
from .noise_generator import SilverNoiseGenerator


class TrafficObfuscator:
    """
    Traffic obfuscator using silver ratio padding.

    Transforms traffic to maintain the silver ratio identity:
    η² + λ² = 1

    Where:
    - η² (0.5) = real traffic portion
    - λ² (0.5) = padding/chaff portion
    """

    # Standard packet sizes (MTU-aligned)
    STANDARD_SIZES = [128, 256, 512, 1024, 1280, 1400, 1500]

    def __init__(
        self,
        config: Optional[ObfuscationConfig] = None,
        noise_gen: Optional[SilverNoiseGenerator] = None,
    ):
        """
        Initialize the traffic obfuscator.

        Args:
            config: Obfuscation configuration
            noise_gen: Noise generator for padding
        """
        self.config = config or ObfuscationConfig()
        self.noise_gen = noise_gen or SilverNoiseGenerator()

        # Statistics
        self._total_real_bytes = 0
        self._total_padded_bytes = 0
        self._packets_processed = 0

    def obfuscate(self, data: bytes) -> ObfuscationResult:
        """
        Obfuscate a data packet.

        Applies silver-ratio padding to achieve η² + λ² = 1 balance.

        Args:
            data: Original packet data

        Returns:
            ObfuscationResult with padded data
        """
        original_size = len(data)

        if not self.config.enable_padding:
            return ObfuscationResult(
                original_size=original_size,
                original_data=data,
                obfuscated_size=original_size,
                obfuscated_data=data,
                padding_size=0,
            )

        # Calculate silver padding
        padding_size = self._calculate_padding_size(original_size)

        # Generate padding
        padding = self.noise_gen.generate_bytes(padding_size)

        # Combine data with padding
        # Format: [length:4][data][padding]
        obfuscated = self._pack_with_padding(data, padding)

        # Update statistics
        self._total_real_bytes += original_size
        self._total_padded_bytes += len(obfuscated)
        self._packets_processed += 1

        result = ObfuscationResult(
            original_size=original_size,
            original_data=data,
            obfuscated_size=len(obfuscated),
            obfuscated_data=obfuscated,
            padding_size=padding_size,
            padding_type="silver",
        )
        result.calculate_metrics()

        return result

    def deobfuscate(self, data: bytes) -> bytes:
        """
        Remove obfuscation from a packet.

        Args:
            data: Obfuscated packet data

        Returns:
            Original data without padding
        """
        if len(data) < 4:
            return data

        # Extract length prefix
        length = int.from_bytes(data[:4], "big")

        if length > len(data) - 4:
            # Invalid length, return as-is
            return data

        # Extract original data
        return data[4:4 + length]

    def _calculate_padding_size(self, payload_size: int) -> int:
        """
        Calculate padding size for silver ratio balance.

        Target: real data = η² of total, padding = λ² of total
        When η² = λ² = 0.5, padding equals payload.
        """
        # Base silver padding
        base_padding = silver_padding(payload_size)

        # Apply configured ratio adjustment
        adjusted = int(base_padding * self.config.target_padding_ratio / LAMBDA_SQUARED)

        # Ensure minimum packet size
        total_size = payload_size + 4 + adjusted  # 4 bytes for length prefix
        if total_size < self.config.min_packet_size:
            adjusted = self.config.min_packet_size - payload_size - 4

        # Respect maximum
        if total_size > self.config.max_packet_size:
            adjusted = self.config.max_packet_size - payload_size - 4

        return max(0, adjusted)

    def _pack_with_padding(self, data: bytes, padding: bytes) -> bytes:
        """Pack data with length prefix and padding."""
        length_prefix = len(data).to_bytes(4, "big")
        return length_prefix + data + padding

    def normalize_size(self, data: bytes) -> bytes:
        """
        Normalize packet to standard size.

        Pads to next standard size for size uniformity.
        """
        current_size = len(data)

        # Find next standard size
        target_size = self.config.max_packet_size
        for size in self.STANDARD_SIZES:
            if size >= current_size:
                target_size = size
                break

        if current_size >= target_size:
            return data

        # Pad to target
        padding_needed = target_size - current_size
        padding = self.noise_gen.generate_bytes(padding_needed)

        return data + padding

    def get_profile(self) -> TrafficProfile:
        """Get current traffic profile statistics."""
        profile = TrafficProfile(
            total_bytes=self._total_padded_bytes,
            real_bytes=self._total_real_bytes,
            padding_bytes=self._total_padded_bytes - self._total_real_bytes,
            total_packets=self._packets_processed,
            real_packets=self._packets_processed,
        )
        profile.calculate_ratios()
        return profile

    def reset_stats(self) -> None:
        """Reset statistics."""
        self._total_real_bytes = 0
        self._total_padded_bytes = 0
        self._packets_processed = 0


class ConstantBandwidthObfuscator:
    """
    Constant bandwidth obfuscation.

    Maintains constant bandwidth regardless of actual traffic,
    making it impossible to infer activity from bandwidth usage.
    """

    def __init__(
        self,
        target_bandwidth_bps: int = 1_000_000,  # 1 Mbps
        packet_interval_ms: float = 10.0,
    ):
        """
        Initialize constant bandwidth obfuscator.

        Args:
            target_bandwidth_bps: Target bandwidth in bits per second
            packet_interval_ms: Interval between packets
        """
        self.target_bandwidth_bps = target_bandwidth_bps
        self.packet_interval_ms = packet_interval_ms

        # Calculate packet size for target bandwidth
        packets_per_second = 1000.0 / packet_interval_ms
        self.target_packet_size = int(target_bandwidth_bps / 8 / packets_per_second)

        self.noise_gen = SilverNoiseGenerator()

        # Queue for real data
        self._data_queue: List[bytes] = []
        self._queue_offset = 0

    def queue_data(self, data: bytes) -> None:
        """Queue real data for transmission."""
        self._data_queue.append(data)

    def get_next_packet(self) -> Tuple[bytes, bool]:
        """
        Get next packet to send.

        Returns:
            Tuple of (packet_data, is_real_data)
        """
        packet = bytearray()
        is_real = False

        # Try to fill from queue
        bytes_needed = self.target_packet_size - 4  # Reserve 4 for header

        while self._data_queue and len(packet) < bytes_needed:
            chunk = self._data_queue[0]
            remaining = bytes_needed - len(packet)

            if len(chunk) <= remaining:
                # Take whole chunk
                packet.extend(chunk)
                self._data_queue.pop(0)
                is_real = True
            else:
                # Take partial chunk
                packet.extend(chunk[:remaining])
                self._data_queue[0] = chunk[remaining:]
                is_real = True
                break

        # Pad with noise to target size
        if len(packet) < bytes_needed:
            padding = self.noise_gen.generate_bytes(bytes_needed - len(packet))
            packet.extend(padding)

        # Add header indicating real data length
        real_length = len(packet) if is_real else 0
        header = real_length.to_bytes(4, "big")

        return bytes(header) + bytes(packet), is_real

    def get_queue_size(self) -> int:
        """Get current queue size in bytes."""
        return sum(len(d) for d in self._data_queue)


class SizeBucketObfuscator:
    """
    Size bucket obfuscation.

    Pads all packets to one of a fixed set of sizes,
    reducing information leaked through packet sizes.
    """

    # Default size buckets (powers of 2 up to MTU)
    DEFAULT_BUCKETS = [64, 128, 256, 512, 1024, 1500]

    def __init__(
        self,
        buckets: Optional[List[int]] = None,
        noise_gen: Optional[SilverNoiseGenerator] = None,
    ):
        """
        Initialize size bucket obfuscator.

        Args:
            buckets: List of allowed packet sizes
            noise_gen: Noise generator for padding
        """
        self.buckets = sorted(buckets or self.DEFAULT_BUCKETS)
        self.noise_gen = noise_gen or SilverNoiseGenerator()

    def obfuscate(self, data: bytes) -> bytes:
        """
        Pad data to next bucket size.

        Args:
            data: Original data

        Returns:
            Data padded to bucket size
        """
        current_size = len(data) + 4  # Include length prefix
        target_bucket = self.buckets[-1]  # Default to largest

        for bucket in self.buckets:
            if bucket >= current_size:
                target_bucket = bucket
                break

        # Calculate padding needed
        padding_size = target_bucket - current_size

        # Generate padding
        padding = self.noise_gen.generate_bytes(padding_size)

        # Pack: [length:4][data][padding]
        length_prefix = len(data).to_bytes(4, "big")
        return length_prefix + data + padding

    def deobfuscate(self, data: bytes) -> bytes:
        """Extract original data from bucketed packet."""
        if len(data) < 4:
            return data

        length = int.from_bytes(data[:4], "big")
        return data[4:4 + length]

    def get_bucket_for_size(self, size: int) -> int:
        """Get the bucket a given size would fall into."""
        for bucket in self.buckets:
            if bucket >= size + 4:
                return bucket
        return self.buckets[-1]
