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

Same core pattern as `claude-ops-agent` (self-reported confidence +
deterministic escalation, not model-decided), but the actual gate logic is
different because the cost of error isn't symmetric here the way it is for
IT-ops ticket routing: missing a real security incident is far worse than
an analyst spending a minute clearing a false positive. So
`decide_escalation()` escalates **critical severity unconditionally** -
regardless of how confident the model claims to be, a SOC shouldn't let an
LLM auto-close its own highest-severity bucket - plus the same low-
confidence and off-taxonomy-category triggers used elsewhere in this
portfolio. This mirrors the same 2 DoD AI Ethical Principles cited in
`claude-ops-agent`'s README (Traceable, Governable), applied to the specific
risk profile of a SOC/NOC rather than copied verbatim.

`validate_triage_response()` is the other new piece: because this repo
sends one batched call covering every alert (not one tool-use call per item
like `claude-ops-agent`), a malformed response risks silently corrupting or
dropping an entire batch of alerts at once. It checks every alert got
answered exactly once, severities/confidences are in-range, and
high/critical severities actually got the required incident note - with one
bounded corrective retry (same reflection pattern as the other two repos in
this portfolio) before raising a hard, actionable error.

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
| Exact severity-tier match vs. real NVD CVSS | 19/20 (95%) |
| Within one tier | 20/20 (100%) |
| Of the 1 miss, caught by the escalation gate | 0/1 (0%) - see why below |

**A number that changed between runs, reported honestly rather than
cherry-picked.** An earlier version of this README cited 10/20 (50%) exact-
match from an earlier live run. Re-running the identical script (same
`RANDOM_SEED = 42`, same sampling code) now produces 19/20 (95%) - not
because the code changed, but because CISA's KEV catalog has grown since
the original run, so the same random seed over a longer list draws a
different 20 CVEs. **Both numbers are real, measured results of the same
benchmark at different points in time** - this repo doesn't quietly swap in
whichever run looks better; a benchmark tied to a live, growing public feed
will drift, and that's disclosed rather than hidden.

That re-run also **breaks a previously-stated pattern**: the old README
claimed every mismatch was Claude rating something more severe than the
official CVSS score, never less. This run's single miss
(`CVE-2026-42897`, NVD `HIGH` -> Claude `MEDIUM`) is the opposite direction
- an under-rate, not an over-rate. The "usually over-rates a currently-
exploited CVE" tendency remains directionally real (it's the pattern in
19 of 20 correct-or-over calls here), but "always" was too strong a claim
from a 20-sample benchmark and is corrected here rather than left standing.
Worth noting for the escalation gate specifically: that one miss carried
confidence exactly `0.70`, the escalation threshold - it did not escalate
only because the gate uses strict `<`, a real boundary case now on record.

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
