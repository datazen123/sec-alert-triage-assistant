"""Offline unit tests for triage.py's deterministic functions - no API key needed."""
import pytest

from triage import extract_json, parse_log


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
