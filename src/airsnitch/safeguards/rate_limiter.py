"""Token bucket rate limiter for packet injection."""

from __future__ import annotations

import time
from threading import Lock

from airsnitch.config import DEFAULT_PPS


class RateLimiter:
    """Token bucket rate limiter.

    Ensures packet sends don't exceed configured packets-per-second.
    Thread-safe.
    """

    def __init__(self, pps: int = DEFAULT_PPS):
        self._pps = max(1, pps)
        self._tokens = float(pps)
        self._max_tokens = float(pps)
        self._last_refill = time.monotonic()
        self._lock = Lock()

    @property
    def pps(self) -> int:
        return self._pps

    def acquire(self, count: int = 1) -> None:
        """Block until `count` tokens are available."""
        while True:
            with self._lock:
                self._refill()
                if self._tokens >= count:
                    self._tokens -= count
                    return
            # Sleep for approximately the time needed for one token
            time.sleep(1.0 / self._pps)

    def try_acquire(self, count: int = 1) -> bool:
        """Try to acquire tokens without blocking. Returns True if acquired."""
        with self._lock:
            self._refill()
            if self._tokens >= count:
                self._tokens -= count
                return True
            return False

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self._max_tokens, self._tokens + elapsed * self._pps)
        self._last_refill = now
