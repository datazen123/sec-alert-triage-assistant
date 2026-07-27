# Context for Claude Code working in this repo

This repo is one of a **10-repo public portfolio** (github.com/datazen123)
demonstrating real, live-verified agentic AI engineering for a specific
DoD-contractor job pursuit. Full README below covers this repo in detail;
this file covers conventions and status a coding agent needs before making
changes.

## This repo's role

Claude batch-classifies firewall/IDS-style alert severity, with a
**deterministic escalation gate** (`decide_escalation()` in `triage.py`)
tuned for security triage's error asymmetry: critical severity escalates
**unconditionally**, regardless of model confidence - a SOC shouldn't let
an LLM auto-close its own highest-severity bucket. `validate_triage_response()`
catches a malformed batch response before any of it is trusted, with one
bounded corrective retry.

**Status (2026-07-27)**: 16/16 tests passing, live-verified. Real
benchmark against CISA KEV vs. official NIST NVD CVSS ground truth: 19/20
(95%) exact-match on this run - a notably different number than the
previously-documented 50%, because the underlying CISA KEV catalog grew
between runs (same random seed, different sample) - both numbers are real
and documented, not cherry-picked. Also found and corrected a stale claim
in the README ("always over-rates, never under-rates") that a fresh run
disproved.

## Non-negotiable discipline this whole portfolio follows

1. Never fabricate a source - every real-data claim is independently
   fetched/verified. If a primary source can't be reached, say so plainly
   rather than guess.
2. Deterministic code owns any mechanical computation/decision; Claude
   only handles the genuinely ambiguous/language part.
3. Live-verify against the real Anthropic API before claiming a result -
   report actual measured numbers, including when they're unflattering or
   change between runs.
4. Synthetic demo data is always labeled as synthetic; real external data
   is cited with exact source/rule IDs.
5. Every repo has a pytest suite, GitHub Actions CI, a "Security notes"
   README section, and pinned dependencies.
6. No real client, unit, or classified-sounding content ever.
7. Ask Sage (not Claude directly) is named as the realistic DoD/DIB
   production deployment path in every repo's README.

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env   # fill in your own ANTHROPIC_API_KEY, never commit it
pytest -q
```

Full cross-repo strategy, founder research, and environment notes live in
the private `datazen123/securebine-portfolio-context` repo - not
duplicated here since this repo is public.
