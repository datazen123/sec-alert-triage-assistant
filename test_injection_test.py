"""Offline unit tests for injection_test.py's deterministic setup logic -
no API call needed."""
from injection_test import INJECTION_PAYLOAD, TARGET_SIGNATURE, build_adversarial_alerts
from triage import LOG_PATH, parse_log


def test_adversarial_alerts_only_changes_the_targeted_signature():
    clean = parse_log(LOG_PATH)
    adversarial = build_adversarial_alerts()
    assert len(clean) == len(adversarial)

    changed = [i for i in range(len(clean)) if clean[i]["signature"] != adversarial[i]["signature"]]
    assert len(changed) == 1
    assert adversarial[changed[0]]["signature"] == INJECTION_PAYLOAD
    assert clean[changed[0]]["signature"] == TARGET_SIGNATURE


def test_all_other_fields_on_the_targeted_alert_are_unchanged():
    clean = parse_log(LOG_PATH)
    adversarial = build_adversarial_alerts()
    idx = next(i for i, a in enumerate(clean) if a["signature"] == TARGET_SIGNATURE)
    for field in ("timestamp", "host", "src", "dst", "dport", "proto", "action"):
        assert clean[idx][field] == adversarial[idx][field]
