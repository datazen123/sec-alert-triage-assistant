"""
LLM-assisted security alert triage.

Parses synthetic firewall/IDS-style alert lines, sends the batch to Claude for
severity classification + short incident notes, and prints a triage report
sorted by severity. This is a demonstration over synthetic, clearly-labeled
sample data only - not connected to any real monitoring system.

Claude self-reports a confidence score per alert alongside severity/category.
A deterministic gate (`decide_escalation`, plain Python, not model-decided)
then splits results into "escalate to analyst" vs. "auto-file": critical
severity always escalates, regardless of confidence - a SOC shouldn't let an
LLM auto-close its highest-severity bucket - and low confidence or an
off-taxonomy category escalate too. `validate_triage_response()` also checks
the whole batch is well-formed (every alert answered exactly once, valid
severity/category, incident_note present where required) before any of it is
trusted, with one bounded corrective retry if it isn't.

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
KNOWN_CATEGORIES = {
    "reconnaissance", "credential_attack", "malware", "data_exfiltration",
    "policy_violation", "benign_anomaly",
}
CODE_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)

# Deterministic escalation gate - not model-decided. Security triage has an
# asymmetric cost of error (a missed real incident is far worse than an
# analyst spending a minute clearing a false positive), so this is
# deliberately more conservative than claude-ops-agent's IT-triage gate:
# critical severity escalates unconditionally, full stop, regardless of how
# confident the model claims to be.
CONFIDENCE_ESCALATION_THRESHOLD = 0.7


def decide_escalation(severity: str, confidence: float, category: str | None = None) -> tuple[bool, str | None]:
    """Pure function - no API call, no randomness, exhaustively unit tested.
    `category` is optional: benchmark.py's CVE-severity scenario has no
    category taxonomy to check, so that branch is simply skipped there
    rather than forced to always fire."""
    reasons = []
    if severity == "critical":
        reasons.append("critical severity (always escalated regardless of confidence)")
    if confidence < CONFIDENCE_ESCALATION_THRESHOLD:
        reasons.append(f"low self-reported confidence ({confidence:.2f} < {CONFIDENCE_ESCALATION_THRESHOLD})")
    if category is not None and category not in KNOWN_CATEGORIES:
        reasons.append(f"off-taxonomy category ({category!r})")
    if reasons:
        return True, "; ".join(reasons)
    return False, None


def validate_triage_response(alerts: list[dict], results: list[dict]) -> list[str]:
    """Deterministic response validator - checks the whole batch is
    well-formed before any of it is trusted. Returns a list of error strings
    (empty if the response is clean)."""
    errors = []
    seen_indices = set()
    for r in results:
        idx = r.get("alert_index")
        if idx in seen_indices:
            errors.append(f"duplicate alert_index {idx}")
        seen_indices.add(idx)

        if r.get("severity") not in SEVERITY_ORDER:
            errors.append(f"alert_index {idx}: invalid severity {r.get('severity')!r}")

        confidence = r.get("confidence")
        if not isinstance(confidence, (int, float)) or not (0.0 <= confidence <= 1.0):
            errors.append(f"alert_index {idx}: confidence {confidence!r} is not a number in [0.0, 1.0]")

        if r.get("severity") in ("critical", "high") and not r.get("incident_note", "").strip():
            errors.append(f"alert_index {idx}: severity {r.get('severity')} requires a non-empty incident_note")

    expected_indices = set(range(len(alerts)))
    missing = expected_indices - seen_indices
    if missing:
        errors.append(f"missing alert_index values: {sorted(missing)}")
    extra = seen_indices - expected_indices
    if extra:
        errors.append(f"alert_index values with no matching alert: {sorted(extra)}")

    return errors


def extract_json(text: str) -> list:
    """Claude sometimes wraps JSON in ```json fences even when told not to - strip them."""
    return json.loads(CODE_FENCE_RE.sub("", text.strip()).strip())

SYSTEM_PROMPT = """You are a security operations triage assistant. You will be
given a batch of parsed firewall/IDS alerts (synthetic sample data). For each
alert, assign a severity (critical, high, medium, low, info), a likely
category (reconnaissance, credential_attack, malware, data_exfiltration,
policy_violation, or benign_anomaly), and your own confidence in that call
from 0.0 to 1.0. Report confidence honestly: a low score routes the alert to
a human analyst instead of auto-filing, which is the safe outcome, not a
penalty. For severity high or critical, include a short draft incident note
(2-3 sentences) an analyst could paste into a ticket - this is required, not
optional, for those two severities. For lower severities, leave incident_note
as an empty string.

Reply with ONLY a JSON array, one object per alert in the same order given, each:
{"alert_index": <int>, "severity": "...", "category": "...", "confidence": <0.0-1.0>, "incident_note": "..."}
"""

CORRECTION_PROMPT_TEMPLATE = """Your previous response failed automated
validation with these errors:

{errors}

Return a corrected, complete JSON array covering ALL {n} alerts again (same
format as before, no markdown fences) - fix only what's wrong, don't change
calls that weren't flagged."""


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
    messages = [{"role": "user", "content": prompt}]

    response = client.create(system=SYSTEM_PROMPT, messages=messages)
    text = "".join(b.text for b in response.content if b.type == "text")
    try:
        results = extract_json(text)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Claude's triage response wasn't valid JSON: {exc}\nRaw response:\n{text}") from exc

    errors = validate_triage_response(alerts, results)
    if errors:
        print(f"  (validation found {len(errors)} issue(s) - requesting one correction pass)")
        messages.append({"role": "assistant", "content": text})
        messages.append({"role": "user", "content": CORRECTION_PROMPT_TEMPLATE.format(
            errors="\n".join(f"- {e}" for e in errors), n=len(alerts))})
        response = client.create(system=SYSTEM_PROMPT, messages=messages)
        text = "".join(b.text for b in response.content if b.type == "text")
        try:
            results = extract_json(text)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Correction pass response wasn't valid JSON: {exc}\nRaw response:\n{text}") from exc
        errors = validate_triage_response(alerts, results)
        if errors:
            raise RuntimeError(f"Triage response still invalid after one correction pass: {errors}")

    return results


def main() -> None:
    alerts = parse_log(LOG_PATH)
    print(f"Parsed {len(alerts)} synthetic alerts, sending to Claude for triage...\n")

    client = AnthropicClient()
    triage_results = triage_batch(client, alerts)

    merged = []
    for result in triage_results:
        alert = alerts[result["alert_index"]]
        escalated, escalation_reason = decide_escalation(result["severity"], result["confidence"], result["category"])
        merged.append({**alert, **result, "escalated": escalated, "escalation_reason": escalation_reason})

    merged.sort(key=lambda a: SEVERITY_ORDER.get(a["severity"], 5))
    escalated = [a for a in merged if a["escalated"]]
    auto_filed = [a for a in merged if not a["escalated"]]

    def print_alert(a: dict) -> None:
        print(f"[{a['severity'].upper():>8}] {a['timestamp']}  {a['category']}  (confidence={a['confidence']:.2f})")
        print(f"    {a['signature']}  (src={a['src']} -> dst={a['dst']}:{a['dport']})")
        if a["incident_note"]:
            print(f"    note: {a['incident_note']}")
        if a["escalated"]:
            print(f"    ESCALATED TO ANALYST: {a['escalation_reason']}")
        print()

    print(f"=== Triage report: {len(escalated)} escalated to analyst, {len(auto_filed)} auto-filed ===\n")
    if escalated:
        print("-- Escalated to analyst --")
        for a in escalated:
            print_alert(a)
    if auto_filed:
        print("-- Auto-filed --")
        for a in auto_filed:
            print_alert(a)


if __name__ == "__main__":
    main()
