"""
Real-data benchmark: classifies real, currently-actively-exploited
vulnerabilities from CISA's Known Exploited Vulnerabilities (KEV) catalog,
scored against the official CVSS v3 severity rating from NIST's National
Vulnerability Database (NVD) - real ground truth, not something invented for
this repo.

This is a SEPARATE scenario from triage.py's demo above. CISA KEV/NVD data
is vulnerability-disclosure data (vendor, product, description), not
firewall/IDS log lines - it doesn't replace the log-format demo, it tests
the same underlying severity-classification judgment against a real,
NIST-run ground truth instead of hand-written synthetic alerts.

Run:
    export ANTHROPIC_API_KEY=sk-ant-...
    python benchmark.py
(Takes ~2 minutes: NVD's public API is rate-limited to 5 requests/30s
without an API key, so lookups are paced deliberately.)
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

import requests

from llm_client import AnthropicClient

ROOT = Path(__file__).parent
CODE_FENCE_RE = re.compile(r"^```[a-zA-Z]*\s*|\s*```$", re.MULTILINE)
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
SAMPLE_SIZE = 20
RANDOM_SEED = 42
SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def extract_json(text: str) -> list:
    return json.loads(CODE_FENCE_RE.sub("", text.strip()).strip())


def fetch_kev_sample(n: int) -> list[dict]:
    data = requests.get(KEV_URL, timeout=30).json()
    vulns = data["vulnerabilities"]
    import random
    random.seed(RANDOM_SEED)
    return random.sample(vulns, n)


def fetch_nvd_severity(cve_id: str) -> str | None:
    resp = requests.get(NVD_URL, params={"cveId": cve_id}, timeout=30)
    if resp.status_code != 200:
        return None
    results = resp.json().get("vulnerabilities", [])
    if not results:
        return None
    metrics = results[0]["cve"].get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            entry = metrics[key][0]
            severity = entry.get("cvssData", {}).get("baseSeverity") or entry.get("baseSeverity")
            if severity:
                return severity.upper()
    return None


def main() -> None:
    client = AnthropicClient()

    print(f"Fetching CISA KEV catalog and sampling {SAMPLE_SIZE} entries...")
    kev_sample = fetch_kev_sample(SAMPLE_SIZE)

    print("Looking up official NVD CVSS severity for each (paced for the public rate limit)...")
    entries = []
    for v in kev_sample:
        severity = fetch_nvd_severity(v["cveID"])
        if severity and severity in SEVERITY_ORDER:
            entries.append({
                "cve_id": v["cveID"],
                "vendor_project": v["vendorProject"],
                "product": v["product"],
                "vulnerability_name": v["vulnerabilityName"],
                "short_description": v["shortDescription"],
                "known_ransomware_use": v.get("knownRansomwareCampaignUse", "Unknown"),
                "true_severity": severity,
            })
        time.sleep(6)

    skipped = len(kev_sample) - len(entries)
    print(f"Got official NVD severity for {len(entries)}/{len(kev_sample)} sampled CVEs "
          f"({skipped} skipped - no CVSS v3/v2 data available, e.g. pre-2016 CVEs).\n")

    system_prompt = f"""You are a vulnerability severity classifier. For each
real, currently actively-exploited vulnerability below (from CISA's Known
Exploited Vulnerabilities catalog), classify its severity using the same
4-tier scale as CVSS base severity: {SEVERITY_ORDER}.

Reply with ONLY a JSON array (no markdown fences), one object per entry in
the same order given:
{{"cve_id": "...", "severity": "LOW|MEDIUM|HIGH|CRITICAL"}}"""

    payload = [{k: v for k, v in e.items() if k != "true_severity"} for e in entries]
    response = client.create(
        system=system_prompt,
        messages=[{"role": "user", "content": json.dumps(payload, indent=2)}],
        max_tokens=2048,
    )
    text = "".join(b.text for b in response.content if b.type == "text")
    predictions = {p["cve_id"]: p["severity"].upper() for p in extract_json(text)}

    exact_matches = 0
    within_one_tier = 0
    confusion = []
    for e in entries:
        predicted = predictions.get(e["cve_id"])
        true = e["true_severity"]
        if predicted is None:
            continue
        diff = abs(SEVERITY_ORDER.index(predicted) - SEVERITY_ORDER.index(true))
        if diff == 0:
            exact_matches += 1
        if diff <= 1:
            within_one_tier += 1
        confusion.append((e["cve_id"], true, predicted))

    n = len(entries)
    report = [
        "# CISA KEV / NIST NVD Real-Data Benchmark Report (sec-alert-triage-assistant)",
        "",
        f"- Sampled KEV entries with usable NVD CVSS ground truth: {n} (of {SAMPLE_SIZE} attempted)",
        f"- Exact severity-tier match vs. real NVD CVSS baseSeverity: {exact_matches}/{n} ({exact_matches/n:.0%})",
        f"- Within one tier: {within_one_tier}/{n} ({within_one_tier/n:.0%})",
        "",
        "## Per-CVE result (true NVD severity -> Claude's call)",
    ] + [f"- {cve}: {true} -> {pred}" + ("  MISMATCH" if true != pred else "") for cve, true, pred in confusion]

    (ROOT / "benchmark_report.md").write_text("\n".join(report) + "\n")
    print("\n".join(report))
    print("\nWrote benchmark_report.md")


if __name__ == "__main__":
    main()
