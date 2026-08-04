"""Offline unit tests for calibration_check.py's deterministic bucketing
logic - no API call needed."""
from calibration_check import bucket_for


def test_low_bucket():
    assert bucket_for(0.0) == "low (0.0-0.5)"
    assert bucket_for(0.49) == "low (0.0-0.5)"


def test_medium_bucket():
    assert bucket_for(0.5) == "medium (0.5-0.85)"
    assert bucket_for(0.84) == "medium (0.5-0.85)"


def test_high_bucket():
    assert bucket_for(0.85) == "high (0.85-1.0)"
    assert bucket_for(1.0) == "high (0.85-1.0)"
