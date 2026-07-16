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
  used throughout this repo. An OpenAI-compatible adapter is included for
  the same interface, but has **not** been run against a live OpenAI/Codex
  key in this repo - treat it as reference code until verified.
- `triage.py` - parsing, the batched classification call, and the report.

## Running it

```bash
pip install -r requirements.txt
cp .env.example .env   # fill in your own ANTHROPIC_API_KEY
export $(grep -v '^#' .env | xargs)
python triage.py
```

Built with [Claude Code](https://claude.com/claude-code).
