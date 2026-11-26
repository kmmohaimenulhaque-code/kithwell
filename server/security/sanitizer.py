"""Input sanitization, XSS defense, and path traversal protection for Kithwell."""

from __future__ import annotations

import html
import re
from pathlib import Path
from typing import Any

# Basic HTML tag stripper (no external deps)
_TAG_RE = re.compile(r"<[^>]+>")
_SCRIPT_RE = re.compile(r"<script\b[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL)
_EVENT_RE = re.compile(r"\bon\w+\s*=", re.IGNORECASE)
_JS_URI_RE = re.compile(r"javascript\s*:", re.IGNORECASE)

# SQL injection pattern heuristics (defense-in-depth; primary defense is parameterized queries)
_SQLI_PATTERNS = [
    re.compile(r"(\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b.*\b(FROM|INTO|TABLE|SET)\b)", re.IGNORECASE),
    re.compile(r"(--|#|/\*.*?\*/)", re.IGNORECASE | re.DOTALL),
    re.compile(r"(\bOR\b\s+\d+\s*=\s*\d+)", re.IGNORECASE),
    re.compile(r"(\bAND\b\s+\d+\s*=\s*\d+)", re.IGNORECASE),
]

MAX_JSON_DEPTH = 12
MAX_JSON_SIZE = 512_000  # 512 KB


def strip_html(text: str) -> str:
    """Remove HTML tags and dangerous constructs."""
    if not isinstance(text, str):
        return ""
    text = _SCRIPT_RE.sub("", text)
    text = _EVENT_RE.sub("", text)
    text = _JS_URI_RE.sub("", text)
    text = _TAG_RE.sub("", text)
    return html.escape(text, quote=True)


def sanitize_string(value: Any, max_len: int = 4096) -> str:
    if value is None:
        return ""
    s = str(value).strip()
    if len(s) > max_len:
        s = s[:max_len]
    return strip_html(s)


def looks_like_sqli(value: str) -> bool:
    if not value:
        return False
    for pat in _SQLI_PATTERNS:
        if pat.search(value):
            return True
    return False


def safe_path(base: Path, user_path: str) -> Path | None:
    """Resolve user_path under base; reject path traversal."""
    try:
        candidate = (base / user_path).resolve()
        base_resolved = base.resolve()
        if not str(candidate).startswith(str(base_resolved)):
            return None
        return candidate
    except (OSError, ValueError):
        return None


def check_json_limits(obj: Any, depth: int = 0) -> bool:
    """Return True if object is within depth/size safety limits."""
    if depth > MAX_JSON_DEPTH:
        return False
    if isinstance(obj, dict):
        if len(obj) > 200:
            return False
        return all(check_json_limits(v, depth + 1) for v in obj.values())
    if isinstance(obj, list):
        if len(obj) > 1000:
            return False
        return all(check_json_limits(v, depth + 1) for v in obj)
    return True
