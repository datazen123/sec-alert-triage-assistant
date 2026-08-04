"""
Confidence calibration check.

Applies Tian, Mitchell, Zhou, Sharma, Rafailov, Yao, Finn, Manning,
"Just Ask for Calibration: Strategies for Eliciting Calibrated Confidence
Scores from Language Models Fine-Tuned with Human Feedback"
(https://arxiv.org/abs/2305.14975, EMNLP 2023). The paper's core finding:
asking a model to self-report a verbalized confidence score, in words
rather than reading raw token probabilities, produces meaningfully
better-calibrated confidence than the model's internal probabilities -
but "better than raw logits" isn't the same as "actually calibrated," so
it's worth checking directly rather than assuming.

This repo already self-reports a confidence score on every classification
(`triage.py`'s `confidence` field), and `benchmark.py` already has real
ground truth to check against: 20 real CISA KEV vulnerabilities scored
against their official NVD CVSS severity. This script reuses that same
fetch-and-classify pipeline, then asks the calibration question directly:
when Claude reports high confidence, is it actually more likely to be
correct than when it reports low confidence? A well-calibrated model's
answer should be yes.

This is additive - it doesn't change benchmark.py's own reported numbers,
and it makes its own live KEV/NVD calls rather than reusing a cached
result, so its confidence-vs-accuracy numbers come from a real,
independently-fetched sample (which may differ slightly from
benchmark.py's own last recorded run, for the same reason benchmark.py's
own README section documents: the KEV catalog is a live, growing feed).

Run:
    export ANTHROPIC_API_KEY=sk-ant-...
    python calibration_check.py
(Takes ~2 minutes - same NVD rate-limit pacing as benchmark.py.)
"""
from __future__ import annotations

import json
from pathlib import Path

from benchmark import SAMPLE_SIZE, SEVERITY_ORDER, fetch_kev_sample, fetch_nvd_severity, extract_json
from llm_client import AnthropicClient

ROOT = Path(__file__).parent

# Tian et al.'s own bucketing granularity for verbalized-confidence
# calibration plots - three bands wide enough to hold a meaningful sample
# from a 20-entry benchmark, narrow enough to show a real trend if one exists.
CONFIDENCE_BUCKETS = [(0.0, 0.5, "low (0.0-0.5)"), (0.5, 0.85, "medium (0.5-0.85)"), (0.85, 1.01, "high (0.85-1.0)")]


def bucket_for(confidence: float) -> str:
    for lo, hi, label in CONFIDENCE_BUCKETS:
        if lo <= confidence < hi:
            return label
    return CONFIDENCE_BUCKETS[-1][2]


def main() -> None:
    import time

    client = AnthropicClient()

    print(f"Fetching CISA KEV catalog and sampling {SAMPLE_SIZE} entries...")
    kev_sample = fetch_kev_sample(SAMPLE_SIZE)

    print("Looking up official NVD CVSS severity for each (paced for the public rate limit)...")
    entries = []
    for v in kev_sample:
        severity = fetch_nvd_severity(v["cveID"])
        if severity and severity in SEVERITY_ORDER:
            entries.append({
                "cve_id": v["cveID"], "vendor_project": v["vendorProject"], "product": v["product"],
                "vulnerability_name": v["vulnerabilityName"], "short_description": v["shortDescription"],
                "known_ransomware_use": v.get("knownRansomwareCampaignUse", "Unknown"), "true_severity": severity,
            })
        time.sleep(6)

    print(f"Got official NVD severity for {len(entries)}/{len(kev_sample)} sampled CVEs.\n")

    system_prompt = f"""You are a vulnerability severity classifier. For each
real, currently actively-exploited vulnerability below (from CISA's Known
Exploited Vulnerabilities catalog), classify its severity using the same
4-tier scale as CVSS base severity: {SEVERITY_ORDER}. Also report your own
confidence in that call from 0.0 to 1.0 - be honest, a low score is fine.

Reply with ONLY a JSON array (no markdown fences), one object per entry in
the same order given:
{{"cve_id": "...", "severity": "LOW|MEDIUM|HIGH|CRITICAL", "confidence": <0.0-1.0>}}"""

    payload = [{k: v for k, v in e.items() if k != "true_severity"} for e in entries]
    response = client.create(
        system=system_prompt,
        messages=[{"role": "user", "content": json.dumps(payload, indent=2)}, {"role": "assistant", "content": "["}],
        max_tokens=2048,
    )
    text = "[" + "".join(b.text for b in response.content if b.type == "text")
    parsed = extract_json(text)
    predictions = {p["cve_id"]: (p["severity"].upper(), p.get("confidence")) for p in parsed}

    calls = []
    for e in entries:
        pred_entry = predictions.get(e["cve_id"])
        if pred_entry is None or pred_entry[1] is None:
            continue
        predicted, confidence = pred_entry
        correct = predicted == e["true_severity"]
        calls.append({"cve_id": e["cve_id"], "confidence": confidence, "correct": correct})

    bucket_stats: dict[str, list[bool]] = {label: [] for _, _, label in CONFIDENCE_BUCKETS}
    for c in calls:
        bucket_stats[bucket_for(c["confidence"])].append(c["correct"])

    print("=== Calibration by confidence bucket ===\n")
    results = {}
    for _, _, label in CONFIDENCE_BUCKETS:
        outcomes = bucket_stats[label]
        if not outcomes:
            print(f"{label}: no calls fell in this bucket")
            results[label] = {"n": 0, "accuracy": None}
            continue
        accuracy = sum(outcomes) / len(outcomes)
        print(f"{label}: {sum(outcomes)}/{len(outcomes)} correct ({accuracy:.0%})")
        results[label] = {"n": len(outcomes), "accuracy": accuracy}

    correct_confidences = [c["confidence"] for c in calls if c["correct"]]
    incorrect_confidences = [c["confidence"] for c in calls if not c["correct"]]
    avg_correct = sum(correct_confidences) / len(correct_confidences) if correct_confidences else None
    avg_incorrect = sum(incorrect_confidences) / len(incorrect_confidences) if incorrect_confidences else None

    print(f"\nAverage confidence on CORRECT calls: {avg_correct:.2f}" if avg_correct is not None
          else "\nAverage confidence on CORRECT calls: n/a (no correct calls)")
    print(f"Average confidence on INCORRECT calls: {avg_incorrect:.2f}" if avg_incorrect is not None
          else "Average confidence on INCORRECT calls: n/a (no incorrect calls)")

    if avg_correct is not None and avg_incorrect is not None:
        gap = avg_correct - avg_incorrect
        print(f"\nCalibration gap (correct minus incorrect average confidence): {gap:+.2f}")
        print("Positive means better-calibrated (higher confidence tracks correctness); "
              "near-zero or negative means confidence isn't a useful correctness signal here.")

    full_result = {
        "n_calls": len(calls), "bucket_accuracy": results,
        "avg_confidence_correct": avg_correct, "avg_confidence_incorrect": avg_incorrect,
        "calibration_gap": (avg_correct - avg_incorrect) if (avg_correct is not None and avg_incorrect is not None) else None,
        "calls": calls,
    }
    (ROOT / "calibration_check_result.json").write_text(json.dumps(full_result, indent=2) + "\n")
    print("\nWrote calibration_check_result.json")


if __name__ == "__main__":
    main()
