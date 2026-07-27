"""Offline unit tests for triage.py's deterministic functions - no API key needed."""
import pytest

from triage import decide_escalation, extract_json, parse_log, validate_triage_response


def test_parse_log_extracts_all_fields(tmp_path):
    log = tmp_path / "alerts.log"
    log.write_text(
        '2026-07-10T02:14:31Z host=fw-edge-01 src=203.0.113.44 dst=10.20.5.12 '
        'dport=445 proto=tcp action=blocked signature="SMB anomalous inbound connection attempt"\n'
    )
    alerts = parse_log(log)
    assert len(alerts) == 1
    assert alerts[0]["host"] == "fw-edge-01"
    assert alerts[0]["src"] == "203.0.113.44"
    assert alerts[0]["dport"] == "445"
    assert alerts[0]["signature"] == "SMB anomalous inbound connection attempt"


def test_parse_log_skips_comments_and_blank_lines(tmp_path):
    log = tmp_path / "alerts.log"
    log.write_text(
        "# this is a comment\n"
        "\n"
        '2026-07-10T02:14:31Z host=fw-edge-01 src=1.2.3.4 dst=10.0.0.1 '
        'dport=80 proto=tcp action=blocked signature="test"\n'
    )
    alerts = parse_log(log)
    assert len(alerts) == 1


def test_parse_log_skips_malformed_lines(tmp_path):
    log = tmp_path / "alerts.log"
    log.write_text("this line does not match the expected format at all\n")
    alerts = parse_log(log)
    assert alerts == []


def test_extract_json_strips_fences():
    assert extract_json('```json\n[{"severity": "high"}]\n```') == [{"severity": "high"}]


def test_extract_json_rejects_malformed_json():
    with pytest.raises(Exception):
        extract_json("not json")


# --- decide_escalation: the deterministic human-in-the-loop gate ---

def test_decide_escalation_high_confidence_medium_severity_auto_files():
    escalated, reason = decide_escalation("medium", 0.9, "policy_violation")
    assert escalated is False
    assert reason is None


def test_decide_escalation_critical_always_escalates_even_with_high_confidence():
    escalated, reason = decide_escalation("critical", 0.99, "malware")
    assert escalated is True
    assert "critical" in reason


def test_decide_escalation_low_confidence_escalates():
    escalated, reason = decide_escalation("low", 0.4, "benign_anomaly")
    assert escalated is True
    assert "confidence" in reason


def test_decide_escalation_off_taxonomy_category_escalates():
    escalated, reason = decide_escalation("medium", 0.9, "something_unlisted")
    assert escalated is True
    assert "taxonomy" in reason


def test_decide_escalation_skips_category_check_when_category_is_none():
    """benchmark.py's CVE-severity scenario has no category taxonomy."""
    escalated, reason = decide_escalation("high", 0.9, None)
    assert escalated is False
    assert reason is None


# --- validate_triage_response: the deterministic batch-response validator ---

def _alerts(n):
    return [{"host": f"h{i}"} for i in range(n)]


def _result(idx, severity="medium", confidence=0.9, incident_note=""):
    return {"alert_index": idx, "severity": severity, "category": "policy_violation",
            "confidence": confidence, "incident_note": incident_note}


def test_validate_triage_response_accepts_well_formed_batch():
    results = [_result(0), _result(1, severity="critical", incident_note="Details here.")]
    assert validate_triage_response(_alerts(2), results) == []


def test_validate_triage_response_flags_missing_index():
    results = [_result(0)]
    errors = validate_triage_response(_alerts(2), results)
    assert any("missing alert_index" in e for e in errors)


def test_validate_triage_response_flags_duplicate_index():
    results = [_result(0), _result(0)]
    errors = validate_triage_response(_alerts(1), results)
    assert any("duplicate" in e for e in errors)


def test_validate_triage_response_flags_invalid_severity():
    results = [_result(0, severity="apocalyptic")]
    errors = validate_triage_response(_alerts(1), results)
    assert any("invalid severity" in e for e in errors)


def test_validate_triage_response_flags_out_of_range_confidence():
    results = [_result(0, confidence=1.5)]
    errors = validate_triage_response(_alerts(1), results)
    assert any("confidence" in e for e in errors)


def test_validate_triage_response_flags_missing_incident_note_for_high_severity():
    results = [_result(0, severity="high", incident_note="")]
    errors = validate_triage_response(_alerts(1), results)
    assert any("requires a non-empty incident_note" in e for e in errors)
