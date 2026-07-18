# sec-alert-triage-assistant

An LLM-assisted first-pass triage tool for firewall/IDS-style security alerts:
parses raw alert lines, batches them to Claude for severity classification and
category tagging, and drafts a short incident note for anything high/critical
- then prints a report sorted by severity.

`data/sample_alerts.log` is entirely synthetic sample data written for this
demo. All IP addresses use IANA/RFC 5737 and RFC 1918 documentation and
private ranges - none of this is from any real network, system, client, or
organization.

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
  single batched Claude call -> severity + category + incident_note per alert
        |
        v
  report printed, sorted highest severity first
```

- `llm_client.py` - thin provider adapter. Anthropic is the tested backend
  used throughout this repo. OpenAI and Ask Sage adapters are included for
  the same interface, but have **not** been run against live credentials in
  this repo - treat them as reference code until verified.
- `triage.py` - parsing, the batched classification call, and the report.

## Real-data benchmark

`triage.py` above runs over hand-written synthetic log lines - good for
showing the architecture, not a measurement. `benchmark.py` is a separate,
additive scenario: it pulls 20 real, currently actively-exploited
vulnerabilities from **CISA's Known Exploited Vulnerabilities (KEV)
catalog**, and scores Claude's severity classification against the official
CVSS v3 **baseSeverity** rating from **NIST's National Vulnerability
Database (NVD)** - real ground truth, not something invented for this repo.

**Actual measured result** (20 real CVEs, full detail in
`benchmark_report.md`):

| Metric | Result |
|---|---|
| Exact severity-tier match vs. real NVD CVSS | 10/20 (50%) |
| Within one tier | 20/20 (100%) |

**The interesting part isn't the 50% - it's the direction of every single
mismatch.** Every miss was Claude rating something *more* severe than its
official CVSS score, never less. That's explainable, not a failure: CVSS
scores the vulnerability's technical severity in isolation, while everything
in this sample is, by definition, already being actively exploited in the
wild (that's what "Known Exploited Vulnerabilities" means) - a real,
additional urgency signal that a security analyst (human or LLM) reasonably
weighs on top of the base CVSS score. This is a genuine, known tension in
security triage, reported honestly rather than smoothed over.

```bash
python benchmark.py
```

## Deployment path

This demo calls the Anthropic API directly. A production version for a
DoD-adjacent SOC/NOC would more likely run through
**[Ask Sage](https://www.asksage.ai/)** - the IL5/IL6-authorized multi-model
gateway built specifically for Defense Industrial Base contractors like the
one this demo targets (`llm_client.py` includes an `AskSageClient` built from
Ask Sage's [public API docs](https://github.com/Ask-Sage/AskSage-Open-Source-Community),
untested pending an account) - rather than a direct-to-vendor API call.
GenAI.mil (CDAO's platform for military/civilian personnel, currently Gemini/
Grok/ChatGPT) is the uniformed-personnel-facing analog, not the contractor
path.

## Running it

```bash
pip install -r requirements.txt
cp .env.example .env   # fill in your own ANTHROPIC_API_KEY
export $(grep -v '^#' .env | xargs)
python triage.py
```

## Tests + CI

`test_triage.py` covers the deterministic log parser (field extraction,
comment/blank-line skipping, malformed-line handling) and JSON-fence
stripping - no API key or network needed, safe for CI on every push:

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
