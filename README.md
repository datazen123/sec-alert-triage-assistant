# sec-alert-triage-assistant

An LLM-assisted first-pass triage tool for firewall/IDS-style security alerts:
parses raw alert lines, batches them to Claude for severity classification and
category tagging, and drafts a short incident note for anything high/critical
- then prints a report sorted by severity.

`data/sample_alerts.log` is entirely synthetic sample data written for this
demo. All IP addresses use IANA/RFC 5737 and RFC 1918 documentation and
private ranges - none of this is from any real network, system, client, or
organization.

## Contents

- [Why this exists](#why-this-exists)
- [Architecture](#architecture)
- [Human-in-the-loop gate, tuned for security triage's error asymmetry](#human-in-the-loop-gate-tuned-for-security-triages-error-asymmetry)
- [Real-data benchmark](#real-data-benchmark)
- [Deployment path](#deployment-path)
- [Prerequisites](#prerequisites)
- [Running it](#running-it)
- [Troubleshooting](#troubleshooting)
- [Tests + CI](#tests--ci)
- [Security notes](#security-notes)

## Why this exists

Security teams triage a high volume of alerts where most turns out to be
noise, but the small number of real signals need fast, consistent first-pass
severity judgment before a human analyst looks closer. This shows that first
pass handled by an LLM: parse -> classify -> draft note -> hand a
prioritized, human-reviewable list to an analyst instead of a raw firehose.

## Architecture

```
data/sample_alerts.log
        |
        v
  regex parse into structured alert records
        |
        v
  single batched Claude call -> severity + category + confidence + incident_note per alert
        |
        v
  validate_triage_response() -- deterministic: every alert answered exactly
  once, valid severity/category, confidence in range, incident_note present
  where required -- malformed? one bounded correction pass, then hard fail
        |
        v
  decide_escalation() -- deterministic, not model-decided --
        |                          |
        v                          v
  auto-filed                escalated to analyst
        |                          |
        +---- report printed, split by outcome, severity-sorted ----+
```

- `llm_client.py` - thin provider adapter. Anthropic is the tested backend
  used throughout this repo. OpenAI and Ask Sage adapters are included for
  the same interface, but have **not** been run against live credentials in
  this repo - treat them as reference code until verified.
- `triage.py` - parsing, the batched classification call, response
  validation with a bounded correction pass, the escalation gate, and the
  report.

## Human-in-the-loop gate, tuned for security triage's error asymmetry

Same core pattern as `claude-ops-agent` - self-reported confidence plus a
deterministic escalation gate, not a model-made decision. The gate logic
itself is different here, because the cost of error isn't symmetric the
way it is for IT-ops ticket routing.

Missing a real security incident is far worse than an analyst spending a
minute clearing a false positive. So `decide_escalation()` escalates
**critical severity unconditionally** - regardless of how confident the
model claims to be. A **SOC** (Security Operations Center - the team that
watches and responds to security alerts) shouldn't let an LLM auto-close
its own highest-severity bucket.

Two more triggers, same as elsewhere in this portfolio:

- Low model confidence.

- An **"off-taxonomy"** category - the model tagging an alert with a
  category outside the fixed list it was given, a sign it may be
  improvising rather than classifying.

This mirrors the same 2 DoD AI Ethical Principles cited in
`claude-ops-agent`'s README (Traceable, Governable), applied to the
specific risk profile of a security/network operations center rather than
copied verbatim.

**`validate_triage_response()`** is the other new piece. This repo sends
one batched call covering every alert, not one tool-use call per item
like `claude-ops-agent` - so a malformed response risks silently
corrupting or dropping an entire batch at once. It checks:

- every alert got answered exactly once

- severities/confidences are in-range

- every high/critical severity actually got its required incident note

One bounded corrective retry (same reflection pattern as the other repos
in this portfolio), then a hard, actionable error if it's still wrong.

## Real-data benchmark

`triage.py` above runs over hand-written synthetic log lines - good for
showing the architecture, not a measurement. `benchmark.py` is a separate,
additive scenario: it pulls 20 real, currently actively-exploited
vulnerabilities from **CISA's Known Exploited Vulnerabilities (KEV)
catalog**, and scores Claude's severity classification against the
official CVSS v3 **baseSeverity** rating - the industry-standard "how bad
is this vulnerability" score - from **NIST's National Vulnerability
Database (NVD)**. Real ground truth, not something invented for this repo.

**Actual measured result** (20 real CVEs, full detail in
`benchmark_report.md`):

| Metric | Result |
|---|---|
| Exact severity-tier match vs. real NVD CVSS | 19/20 (95%) |
| Within one tier | 20/20 (100%) |
| Of the 1 miss, caught by the escalation gate | 0/1 (0%) - see why below |

**Why the number changed between runs**

An earlier version of this README cited 10/20 (50%) exact-match from an
earlier live run.

Re-running the identical script (same `RANDOM_SEED = 42`, same sampling
code) now produces 19/20 (95%).

Not because the code changed - because CISA's KEV catalog has grown since
the original run, so the same random seed over a longer list draws a
different 20 CVEs.

Both numbers are real, measured results of the same benchmark at
different points in time. A benchmark tied to a live, growing public feed
will drift - that's disclosed here, not hidden.

**A claim this re-run corrected**

The old README claimed every mismatch was Claude rating something more
severe than the official CVSS score, never less.

This run's single miss (`CVE-2026-42897`, NVD `HIGH` → Claude `MEDIUM`)
is the opposite direction - an under-rate, not an over-rate.

The "usually over-rates a currently-exploited CVE" tendency remains
directionally real - it's the pattern in 19 of the 20 correct-or-over
calls here. But "always" was too strong a claim from a 20-sample
benchmark, corrected here rather than left standing.

**A real boundary case on record**

That one miss carried confidence exactly `0.70` - the escalation
threshold.

It did not escalate, because the gate uses strict `<`. A real edge case,
not a hypothetical one.

```bash
python benchmark.py
```

## Deployment path

This demo calls the Anthropic API directly. A production version for a
DoD-adjacent security/network operations center would more likely run
through **[Ask Sage](https://www.asksage.ai/)** - the **IL5/IL6**-authorized
(DoD Impact Level 5/6, the government's cloud-security certification
tiers for sensitive/controlled data) multi-model gateway built
specifically for Defense Industrial Base contractors like the one this
demo targets (`llm_client.py` includes an `AskSageClient` built from Ask
Sage's [public API docs](https://github.com/Ask-Sage/AskSage-Open-Source-Community),
untested pending an account).

GenAI.mil (CDAO's platform for military/civilian personnel, currently
Gemini/Grok/ChatGPT) is the uniformed-personnel-facing analog, not the
contractor path.

## Prerequisites

Python 3.9 or newer. Check with `python3 --version` before starting.

## Running it

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # fill in your own ANTHROPIC_API_KEY
export $(grep -v '^#' .env | xargs)
python triage.py
```

The `python3 -m venv` step matters, not just good practice: on macOS,
plain `pip install` can silently resolve to a leftover Python 2.7
install instead of Python 3 - see Troubleshooting below.

## Troubleshooting

**`ERROR: Could not find a version that satisfies the requirement
anthropic<1.0.0,>=0.40.0 ... (from versions: none)`, alongside a "Python
2.7 reached end of life" warning:**

Your `pip` command is resolving to a Python 2.7 installation, not Python
3 - common on macOS, where an old Python 2.7 framework install can sit
earlier on `PATH` than Python 3. The `anthropic` package doesn't publish
anything for Python 2 at all, hence "no versions: none" - it's not a
network or permissions problem.

Fix: create and activate a virtual environment first, exactly as shown
above (`python3 -m venv .venv && source .venv/bin/activate`), then run
`pip install` again inside it. If you'd rather not use a venv, run
`python3 -m pip install -r requirements.txt` instead of bare `pip
install` - that forces the install through Python 3's own pip regardless
of what `pip` alone resolves to on your system.

## Tests + CI

`test_triage.py` covers the deterministic log parser (field extraction,
comment/blank-line skipping, malformed-line handling), JSON-fence stripping,
every branch of `decide_escalation` (critical override, low confidence,
off-taxonomy category, category-check skipped when absent), and every
branch of `validate_triage_response` (missing/duplicate index, invalid
severity, out-of-range confidence, missing required incident note) - no API
key or network needed, safe for CI on every push:

```bash
pip install -r requirements-dev.txt
pytest -q
```

## Security notes

- API keys are read from environment variables only, never hardcoded;
  `.env` is gitignored, `.env.example` ships placeholders only.
- Checked (2026-07-18): this repository's full git history contains zero
  occurrences of any real API key.
- Network calls to the Ask Sage gateway have explicit 30s timeouts.
- A malformed/non-JSON model response now raises a clear, actionable
  error (with the raw response attached) instead of an opaque traceback.
- Dependencies are version-pinned with an upper bound
  (`>=X,<NEXT_MAJOR`), not left open-ended.

Built with [Claude Code](https://claude.com/claude-code).
