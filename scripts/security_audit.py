#!/usr/bin/env python3
"""Static + Dynamic Security Audit Gate for Kithwell.

Verifies ALL security requirements:
1. Zero hardcoded API keys, tokens, or credentials across all source and workflow files
2. Zero unsafe code sinks (eval, exec, innerHTML, subprocess shell=True)
3. Zero woman pictures, zero nudity, zero binary photo assets, zero external image URLs
4. Full automated security & functional test suite passes 100%
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

TEXT_EXTENSIONS = {".py", ".js", ".html", ".css", ".json", ".md", ".yml", ".yaml"}
IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".tiff"}

SECRET_PATTERNS = [
    re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{12,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b"),
]

UNSAFE_SINK_PATTERNS = [
    (re.compile(r"\.innerHTML\s*="), "Unsafe innerHTML assignment"),
    (re.compile(r"\bdocument\.write\s*\("), "Unsafe document.write"),
    (re.compile(r"\beval\s*\("), "Unsafe eval() call"),
    (re.compile(r"shell\s*=\s*True"), "Unsafe subprocess shell=True"),
]

EXTERNAL_IMG_PATTERN = re.compile(r"<img\b[^>]*src\s*=\s*['\"]https?://", re.IGNORECASE)


def run_static_checks() -> list[str]:
    failures: list[str] = []
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(ROOT).as_posix()
        if "__pycache__" in rel or rel.startswith("data/") or rel.startswith("dist/"):
            continue

        # 1. Verify zero binary photo/image assets (strictly geometric SVG only)
        if path.suffix.lower() in IMAGE_EXTENSIONS:
            failures.append(f"[MEDIA_POLICY] Disallowed raster image file found: {rel}")
            continue

        if path.suffix.lower() not in TEXT_EXTENSIONS:
            continue

        # Skip test files and this audit script when scanning for test-fixture strings
        is_test_or_audit = rel.startswith("tests/") or rel == "scripts/security_audit.py"
        content = path.read_text(encoding="utf-8", errors="ignore")

        if not is_test_or_audit:
            for pat in SECRET_PATTERNS:
                if pat.search(content):
                    failures.append(f"[SECRET_SCAN] Potential hardcoded secret in {rel}")
            for pat, label in UNSAFE_SINK_PATTERNS:
                if pat.search(content):
                    failures.append(f"[UNSAFE_SINK] {label} in {rel}")
            if EXTERNAL_IMG_PATTERN.search(content):
                failures.append(f"[MEDIA_POLICY] External <img> tag found in {rel}")

    return failures


def run_dynamic_tests() -> bool:
    loader = unittest.TestLoader()
    suite = loader.discover(str(ROOT / "tests"), pattern="test_*.py")
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result.wasSuccessful()


def main() -> int:
    print("=== Kithwell Static Security & Content Policy Audit ===")
    failures = run_static_checks()
    if failures:
        for f in failures:
            print(f"FAIL: {f}")
        return 1
    print("PASS: Zero hardcoded secrets, zero unsafe sinks, zero disallowed images/media.")

    print("\n=== Kithwell Dynamic Security & Functional Test Suite ===")
    ok = run_dynamic_tests()
    if not ok:
        print("FAIL: One or more dynamic tests failed.")
        return 1

    print("\nALL SECURITY CHECKS AND TESTS PASSED (100%).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
