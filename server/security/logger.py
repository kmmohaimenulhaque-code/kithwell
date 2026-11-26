"""Zero-leak structured logger for Kithwell.

Redacts API keys, passwords, emails, phones, SSNs, and other PHI/PII from
all log messages and exception tracebacks before they ever hit stdout/stderr
or any log sink.
"""

from __future__ import annotations

import logging
import re
import sys
from typing import Any

# Patterns that must never appear in logs
_REDACT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{12,}\b"), "[REDACTED_KEY]"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"), "[REDACTED_KEY]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_AWS]"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"), "[REDACTED_GCP]"),
    (re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b"), "[REDACTED_GH]"),
    (re.compile(r"\bBearer\s+[A-Za-z0-9._-]{20,}\b", re.IGNORECASE), "Bearer [REDACTED]"),
    (re.compile(r"\bx-api-key[=:\s]+[A-Za-z0-9._-]{10,}\b", re.IGNORECASE), "x-api-key=[REDACTED]"),
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "[REDACTED_EMAIL]"),
    (re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"), "[REDACTED_PHONE]"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED_SSN]"),
    (re.compile(r"\b(?:password|passwd|pwd|secret|token)\s*[=:]\s*\S+", re.IGNORECASE), "[REDACTED_SECRET]"),
]


def _redact(text: str) -> str:
    for pat, repl in _REDACT_PATTERNS:
        text = pat.sub(repl, text)
    return text


class ZeroLeakFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        original = super().format(record)
        return _redact(original)


class ZeroLeakLogger:
    """Thin wrapper that forces redaction on every emit."""

    def __init__(self, name: str = "kithwell", level: int = logging.INFO) -> None:
        self._logger = logging.getLogger(name)
        self._logger.setLevel(level)
        if not self._logger.handlers:
            handler = logging.StreamHandler(sys.stderr)
            handler.setFormatter(
                ZeroLeakFormatter("%(asctime)s | %(levelname)-7s | %(name)s | %(message)s")
            )
            self._logger.addHandler(handler)

    def debug(self, msg: Any, *args: Any, **kwargs: Any) -> None:
        self._logger.debug(_redact(str(msg)), *args, **kwargs)

    def info(self, msg: Any, *args: Any, **kwargs: Any) -> None:
        self._logger.info(_redact(str(msg)), *args, **kwargs)

    def warning(self, msg: Any, *args: Any, **kwargs: Any) -> None:
        self._logger.warning(_redact(str(msg)), *args, **kwargs)

    def error(self, msg: Any, *args: Any, **kwargs: Any) -> None:
        self._logger.error(_redact(str(msg)), *args, **kwargs)

    def exception(self, msg: Any, *args: Any, **kwargs: Any) -> None:
        self._logger.exception(_redact(str(msg)), *args, **kwargs)


# Module-level singleton
log = ZeroLeakLogger()
