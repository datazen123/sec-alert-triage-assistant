"""
Self-consistency check: does Claude assign the same severity to the same
alert across multiple independent samples of the same batched call?

Applies Wang, Wei, Schuurmans, Le, Chi, Narang, Chowdhery, Zhou,
"Self-Consistency Improves Chain of Thought Reasoning in Language Models"
(https://arxiv.org/abs/2203.11171, ICLR 2023) to this repo's
severity-assignment call: instead of trusting one sample, this calls
`triage_batch()` `--samples` times (default 3) against the identical
alert log, then deterministically majority-votes the severity for each
alert - the same "deterministic code owns the decision, Claude only
proposes" split this whole portfolio already uses, extended one level
further: Claude proposes N times, not once, and code picks the consensus.

Only samples that pass `validate_triage_response()` structural validation
are counted - a malformed sample is excluded from voting, not silently
included.

This is additive - it doesn't change triage.py's default single-call
behavior. It's a separate, live-measured test of how consistent that
call's severity judgment actually is, not a claim about its accuracy.

Run:
    export ANTHROPIC_API_KEY=sk-ant-...
    python self_consistency_check.py [--samples N]
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from llm_client import AnthropicClient
from triage import LOG_PATH, parse_log, triage_batch, validate_triage_response

ROOT = Path(__file__).parent
DEFAULT_SAMPLES = 3


def sample_once(client: AnthropicClient, alerts: list[dict]) -> dict:
    """One independent sample of the batched triage call, validated the
    same way the primary pipeline validates it (including its own bounded
    correction pass on a malformed response). A sample still invalid after
    that is excluded from voting entirely, not silently counted."""
    try:
        results = triage_batch(client, alerts)
    except RuntimeError:
        return {}
    if validate_triage_response(alerts, results):
        return {}
    return {r["alert_index"]: r for r in results}


def majority_vote(severities: list[str]) -> tuple[str, bool]:
    """Deterministic aggregation - no LLM judgment. Returns the most common
    severity and whether it was unanimous across all samples given."""
    counts = Counter(severities)
    winner, count = counts.most_common(1)[0]
    return winner, count == len(severities)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--samples", type=int, default=DEFAULT_SAMPLES)
    args = parser.parse_args()

    client = AnthropicClient()
    alerts = parse_log(LOG_PATH)

    print(f"Sampling the batched triage call {args.samples} independent times "
          f"against the identical {len(alerts)}-alert log...\n")

    samples = [sample_once(client, alerts) for _ in range(args.samples)]
    clean_samples = [s for s in samples if s]
    if len(clean_samples) < len(samples):
        print(f"  ({len(samples) - len(clean_samples)}/{len(samples)} sample(s) failed structural "
              f"validation and were excluded from voting)\n")

    results = {}
    for idx in range(len(alerts)):
        severities = [s[idx]["severity"] for s in clean_samples if idx in s]
        if len(severities) < len(clean_samples) or not clean_samples:
            results[idx] = {
                "severities_by_sample": severities,
                "consensus": None,
                "unanimous": False,
                "note": f"only {len(severities)}/{len(clean_samples)} valid samples covered this alert",
            }
            continue
        winner, unanimous = majority_vote(severities)
        results[idx] = {"severities_by_sample": severities, "consensus": winner, "unanimous": unanimous}

    unanimous_count = sum(1 for r in results.values() if r["unanimous"])
    total = len(results)

    print("=== Self-consistency results ===\n")
    for idx, r in results.items():
        if r["consensus"] is None:
            tag = "INCOMPLETE"
        elif r["unanimous"]:
            tag = "UNANIMOUS"
        else:
            tag = "SPLIT"
        print(f"[{tag}] alert {idx} ({alerts[idx]['signature']}): "
              f"{r['severities_by_sample']} -> consensus: {r['consensus']}")

    complete = [r for r in results.values() if r["consensus"] is not None]
    print(f"\nAlerts covered by every valid sample: {len(complete)}/{total}")
    print(f"Unanimous agreement among those: {unanimous_count}/{len(complete)} "
          f"({round(100 * unanimous_count / len(complete)) if complete else 0}%)")

    (ROOT / "self_consistency_result.json").write_text(json.dumps(results, indent=2) + "\n")
    print("Wrote self_consistency_result.json")


if __name__ == "__main__":
    main()
