"""
LLM-assisted security alert triage.

Parses synthetic firewall/IDS-style alert lines, sends the batch to Claude for
severity classification + short incident notes, and prints a triage report
sorted by severity. This is a demonstration over synthetic, clearly-labeled
sample data only - not connected to any real monitoring system.

Run:
    export ANTHROPIC_API_KEY=sk-ant-...
    python triage.py
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from llm_client import AnthropicClient

LOG_PATH = Path(__file__).parent / "data" / "sample_alerts.log"

LINE_RE = re.compile(
    r"^(?P<timestamp>\S+) host=(?P<host>\S+) src=(?P<src>\S+) dst=(?P<dst>\S+) "
    r"dport=(?P<dport>\S+) proto=(?P<proto>\S+) action=(?P<action>\S+) "
    r'signature="(?P<signature>[^"]+)"$'
)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
CODE_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)


def extract_json(text: str) -> list:
    """Claude sometimes wraps JSON in ```json fences even when told not to - strip them."""
    return json.loads(CODE_FENCE_RE.sub("", text.strip()).strip())

SYSTEM_PROMPT = """You are a security operations triage assistant. You will be
given a batch of parsed firewall/IDS alerts (synthetic sample data). For each
alert, assign a severity (critical, high, medium, low, info) and a likely
category (e.g. reconnaissance, credential_attack, malware, data_exfiltration,
policy_violation, benign_anomaly). For severity high or critical, include a
short draft incident note (2-3 sentences) an analyst could paste into a ticket.
For lower severities, leave incident_note as an empty string.

Reply with ONLY a JSON array, one object per alert in the same order given, each:
{"alert_index": <int>, "severity": "...", "category": "...", "incident_note": "..."}
"""


def parse_log(path: Path) -> list[dict]:
    alerts = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = LINE_RE.match(line)
        if match:
            alerts.append(match.groupdict())
    return alerts


def triage_batch(client: AnthropicClient, alerts: list[dict]) -> list[dict]:
    indexed = [{"alert_index": i, **a} for i, a in enumerate(alerts)]
    prompt = f"Alerts:\n{json.dumps(indexed, indent=2)}"
    response = client.create(system=SYSTEM_PROMPT, messages=[{"role": "user", "content": prompt}])
    text = "".join(b.text for b in response.content if b.type == "text")
    try:
        return extract_json(text)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Claude's triage response wasn't valid JSON: {exc}\nRaw response:\n{text}") from exc


def main() -> None:
    alerts = parse_log(LOG_PATH)
    print(f"Parsed {len(alerts)} synthetic alerts, sending to Claude for triage...\n")

    client = AnthropicClient()
    triage_results = triage_batch(client, alerts)

    merged = []
    for result in triage_results:
        alert = alerts[result["alert_index"]]
        merged.append({**alert, **result})

    merged.sort(key=lambda a: SEVERITY_ORDER.get(a["severity"], 5))

    print("=== Triage report (highest severity first) ===\n")
    for a in merged:
        print(f"[{a['severity'].upper():>8}] {a['timestamp']}  {a['category']}")
        print(f"    {a['signature']}  (src={a['src']} -> dst={a['dst']}:{a['dport']})")
        if a["incident_note"]:
            print(f"    note: {a['incident_note']}")
        print()


if __name__ == "__main__":
    main()
