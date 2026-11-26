"""Per-IP sliding-window rate limiter for Kithwell API routes."""

from __future__ import annotations

import time
from collections import defaultdict, deque
from threading import Lock
from typing import Deque


class SlidingWindowRateLimiter:
    """Simple in-memory sliding window rate limiter.

    Thread-safe. Suitable for single-process local-first deployment.
    """

    def __init__(self, max_requests: int = 60, window_seconds: float = 60.0) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._hits: dict[str, Deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def allow(self, key: str) -> tuple[bool, int, float]:
        """Return (allowed, remaining, retry_after_seconds)."""
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            # Drop expired timestamps
            while q and (now - q[0]) > self.window_seconds:
                q.popleft()
            if len(q) >= self.max_requests:
                retry_after = self.window_seconds - (now - q[0]) if q else self.window_seconds
                return False, 0, max(0.0, retry_after)
            q.append(now)
            remaining = self.max_requests - len(q)
            return True, remaining, 0.0

    def reset(self, key: str | None = None) -> None:
        with self._lock:
            if key is None:
                self._hits.clear()
            elif key in self._hits:
                del self._hits[key]
