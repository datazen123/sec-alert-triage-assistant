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

Built with [Claude Code](https://claude.com/claude-code).
