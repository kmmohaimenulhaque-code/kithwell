# Kithwell — Local-First Family Caregiving & Longitudinal Health OS

Zero-dependency, offline-first, security-hardened implementation of the **Kithwell** architecture blueprint.

## Quick Start (Zero External Installs Required)

Requires **Python 3.11+** only (uses Python standard library + SQLite WAL + Vanilla ES6 PWA):

```bash
python3 run.py
```

Open **http://127.0.0.1:8765** in your browser.

## Run Full Security Audit & Automated Tests

```bash
python3 scripts/security_audit.py
```

## Implemented Modules & Security Controls

1. **Dual-Persona Sanctuary Interface**: Instant toggle between **Care Circle Command Center** and **Senior Dignity Mode** (`>=60px` touch targets, `16px` buffers, one primary action per screen, Web Speech voice readout).
2. **W3C DTCG 2025.10 OKLCH Design System**: All 23 perceptually uniform tokens (`tokens/kithwell.tokens.json`) compiled across **Sanctuary Light**, **Nocturne Dark**, and **ClearView AAA** (`20.06:1` contrast), plus Reduce Motion & Reduce Transparency toggles.
3. **Failsafe Medication Schedule & Zero-App SMS/Voice Bridge**: Append-only G-Set dose log, supply tracking, customizable escalation cascade, and offline ONC High-Priority DDI checks with verbatim FDA DailyMed SPL citations.
4. **Git-Style Hospital Discharge Diff Engine**: Detects `Added`, `Modified`, `Stopped/Held`, and `Silent Omissions` with a human-in-the-loop commit gate and auto-generated 72-hour transition checklist.
5. **Visit Scribe & Offline Semantic Vault**: Extractive-only summaries with deterministic FDA January 2026 Non-Device topic & refusal guardrails (Care Logistics vs. Clinical Advice Refusal vs. 911 Emergency).
6. **I-PASS Shift Handoff, Care Circle Roles & 2026 $7,500 FSA Ledger**: Role-scoped Care Circle permissions, 60-second I-PASS briefs, and Dependent Care FSA cap tracking.
7. **HL7 SMART Health Link (SHL) Emergency QR & 1-Click Sovereign Export**: Permanent free-tier export to HL7 FHIR R4 Bundle (JSON), Markdown Care Binder, and CSV.
8. **Settings Auto-Update Engine**: Toggleable auto-updates, release channel selector (`stable`, `lts`, `beta`), interval configuration, and mandatory SHA-256 + HMAC cryptographic signature verification.
9. **Hardened Security Posture**:
   - **Rate Limiting**: Per-IP sliding-window limiter (`429 Too Many Requests` + `Retry-After` + `X-RateLimit-*`).
   - **Input Sanitization**: Strict HTML/XSS stripping, parameterized SQLite queries + SQLi pattern defense, path traversal protection, and JSON depth/size caps.
   - **Zero API Keys / Secrets / PHI in Logs**: `ZeroLeakLogger` redacts API keys (`sk-`, `pk_`, `AKIA`, `AIza`, `Bearer`, `x-api-key`), passwords, emails, phones, and SSNs from all logs and tracebacks.
   - **Strict Content Safety Policy**: Strictly geometric clinical SVG icons only — **zero woman pictures, zero human portraits, zero nudity, zero external image URLs**.
