"""
Timing Obfuscator

Obfuscates packet timing using silver ratio mathematics.

Prevents traffic analysis based on timing patterns by:
- Adding silver-scaled jitter
- Using Pell sequence intervals
- Maintaining plausible deniability

Created by: ADZ (Alexander David Zalewski) & Claude Opus 4.5
"""

import sys
import time
import random
from pathlib import Path
from typing import List, Optional, Tuple
from dataclasses import dataclass

# Add parent for silver constants
sys.path.insert(0, str(Path(__file__).parent.parent))
from silver_constants import (
    DELTA_S, TAU, ETA,
    pell, silver_delay_us,
)

from .models import ObfuscationConfig, PrivacyLevel


@dataclass
class TimingDecision:
    """Decision for packet timing."""
    delay_us: int           # Microseconds to wait
    jitter_us: int          # Jitter added
    pattern_index: int      # Position in Pell sequence
    is_silver_timed: bool   # Whether silver timing was applied


class TimingObfuscator:
    """
    Silver-ratio timing obfuscator.

    Uses Pell sequence for timing intervals, creating patterns
    that are deterministic but appear random to observers.
    """

    def __init__(
        self,
        base_interval_us: int = 10_000,  # 10ms
        jitter_factor: float = 0.2,
        use_pell_sequence: bool = True,
    ):
        """
        Initialize timing obfuscator.

        Args:
            base_interval_us: Base timing interval in microseconds
            jitter_factor: Random jitter factor (0-1)
            use_pell_sequence: Use Pell sequence for timing
        """
        self.base_interval_us = base_interval_us
        self.jitter_factor = jitter_factor
        self.use_pell_sequence = use_pell_sequence

        # State
        self._packet_index = 0
        self._pell_cache = [pell(i) for i in range(30)]
        self._last_send_time = 0.0

        # Statistics
        self._total_delays_us = 0
        self._packets_timed = 0

    def get_next_delay(self) -> TimingDecision:
        """
        Get delay for next packet.

        Returns:
            TimingDecision with delay and metadata
        """
        # Base delay from silver calculation
        if self.use_pell_sequence:
            base_delay = silver_delay_us(self._packet_index, self.base_interval_us)
        else:
            base_delay = self.base_interval_us

        # Add jitter
        jitter_range = int(base_delay * self.jitter_factor)
        jitter = random.randint(-jitter_range, jitter_range)
        final_delay = max(0, base_delay + jitter)

        # Update state
        pattern_index = self._packet_index
        self._packet_index = (self._packet_index + 1) % 20

        # Statistics
        self._total_delays_us += final_delay
        self._packets_timed += 1

        return TimingDecision(
            delay_us=final_delay,
            jitter_us=jitter,
            pattern_index=pattern_index,
            is_silver_timed=self.use_pell_sequence,
        )

    async def wait_and_send(self, send_func, data: bytes) -> None:
        """
        Wait appropriate time then send data.

        Args:
            send_func: Async function to call for sending
            data: Data to send
        """
        import asyncio

        decision = self.get_next_delay()

        # Calculate actual wait time based on when we last sent
        now = time.time()
        elapsed_us = int((now - self._last_send_time) * 1_000_000)
        wait_us = max(0, decision.delay_us - elapsed_us)

        if wait_us > 0:
            await asyncio.sleep(wait_us / 1_000_000)

        # Send
        await send_func(data)
        self._last_send_time = time.time()

    def schedule_packets(
        self,
        packet_count: int,
        start_time_us: int = 0,
    ) -> List[Tuple[int, int]]:
        """
        Schedule timing for multiple packets.

        Returns list of (time_us, packet_index) tuples.
        """
        schedule = []
        current_time = start_time_us

        for i in range(packet_count):
            schedule.append((current_time, i))
            decision = self.get_next_delay()
            current_time += decision.delay_us

        return schedule

    def get_average_delay_us(self) -> float:
        """Get average delay across all packets."""
        if self._packets_timed == 0:
            return self.base_interval_us
        return self._total_delays_us / self._packets_timed

    def reset(self) -> None:
        """Reset timing state."""
        self._packet_index = 0
        self._last_send_time = 0.0
        self._total_delays_us = 0
        self._packets_timed = 0


class AdaptiveTimingObfuscator:
    """
    Adaptive timing obfuscator.

    Adjusts timing based on observed patterns and threat level.
    """

    def __init__(self, base_obfuscator: Optional[TimingObfuscator] = None):
        """Initialize adaptive obfuscator."""
        self.base = base_obfuscator or TimingObfuscator()

        # Adaptive state
        self._observed_intervals: List[float] = []
        self._max_observations = 100
        self._current_threat_level = 0.0

    def observe_interval(self, interval_us: float) -> None:
        """Record an observed timing interval."""
        self._observed_intervals.append(interval_us)

        if len(self._observed_intervals) > self._max_observations:
            self._observed_intervals.pop(0)

    def set_threat_level(self, level: float) -> None:
        """Set current threat level (0-1)."""
        self._current_threat_level = max(0, min(1, level))

        # Adjust jitter based on threat
        # Higher threat = more jitter
        self.base.jitter_factor = 0.1 + level * 0.4

    def get_adapted_delay(self) -> TimingDecision:
        """Get delay adapted to current conditions."""
        decision = self.base.get_next_delay()

        # If we have observations, adapt to blend in
        if len(self._observed_intervals) >= 10:
            avg_observed = sum(self._observed_intervals) / len(self._observed_intervals)

            # Blend our timing with observed
            blend_factor = 0.3  # 30% observed, 70% silver
            blended = int(
                decision.delay_us * (1 - blend_factor) +
                avg_observed * blend_factor
            )
            decision.delay_us = blended

        # Add extra randomness at high threat levels
        if self._current_threat_level > 0.5:
            extra_jitter = int(decision.delay_us * self._current_threat_level * 0.2)
            decision.delay_us += random.randint(-extra_jitter, extra_jitter)
            decision.delay_us = max(0, decision.delay_us)

        return decision


class ConstantRateTimer:
    """
    Constant rate timing.

    Sends packets at fixed intervals regardless of actual traffic,
    completely hiding timing patterns.
    """

    def __init__(self, interval_us: int = 10_000):
        """
        Initialize constant rate timer.

        Args:
            interval_us: Fixed interval between packets
        """
        self.interval_us = interval_us
        self._next_send_time = 0.0

    def get_next_send_time(self) -> float:
        """Get next scheduled send time."""
        now = time.time()

        if self._next_send_time <= now:
            # We're behind, send now and reset
            self._next_send_time = now + (self.interval_us / 1_000_000)
            return now

        # Return scheduled time
        scheduled = self._next_send_time
        self._next_send_time += self.interval_us / 1_000_000
        return scheduled

    def time_until_next(self) -> float:
        """Get time in seconds until next send."""
        now = time.time()
        if self._next_send_time <= now:
            return 0.0
        return self._next_send_time - now


class BurstTimingObfuscator:
    """
    Burst timing obfuscation.

    Groups packets into bursts with silver-timed gaps,
    mimicking natural browsing patterns.
    """

    def __init__(
        self,
        burst_size: int = 5,
        intra_burst_us: int = 1_000,    # 1ms between packets in burst
        inter_burst_us: int = 100_000,   # 100ms between bursts
    ):
        """
        Initialize burst timing.

        Args:
            burst_size: Packets per burst
            intra_burst_us: Delay within burst
            inter_burst_us: Delay between bursts
        """
        self.burst_size = burst_size
        self.intra_burst_us = intra_burst_us
        self.inter_burst_us = inter_burst_us

        self._packets_in_current_burst = 0
        self._pell_burst_index = 0

    def get_next_delay(self) -> int:
        """Get delay for next packet."""
        self._packets_in_current_burst += 1

        if self._packets_in_current_burst >= self.burst_size:
            # End of burst, longer delay
            self._packets_in_current_burst = 0
            self._pell_burst_index = (self._pell_burst_index + 1) % 20

            # Silver-scaled inter-burst delay
            pell_factor = pell(self._pell_burst_index)
            delay = self.inter_burst_us + int(pell_factor * 1000)
            return delay
        else:
            # Within burst, short delay with small jitter
            jitter = random.randint(-100, 100)
            return max(0, self.intra_burst_us + jitter)

    def reset(self) -> None:
        """Reset burst state."""
        self._packets_in_current_burst = 0
        self._pell_burst_index = 0
