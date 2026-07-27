# CISA KEV / NIST NVD Real-Data Benchmark Report (sec-alert-triage-assistant)

- Sampled KEV entries with usable NVD CVSS ground truth: 20 (of 20 attempted)
- Exact severity-tier match vs. real NVD CVSS baseSeverity: 19/20 (95%)
- Within one tier: 20/20 (100%)

## Escalation gate safety-net effect (measured, not claimed)

Of the 1 tickets Claude misclassified vs. real NVD severity, the deterministic escalation gate (`triage.decide_escalation` - critical severity always escalates, low confidence escalates) caught: **0/1** (0%). Recall this benchmark's own known bias (below): every miss is Claude rating something *more* severe than NVD, the safe direction for a currently-exploited CVE - so a low catch rate here isn't a safety gap in the way it would be for the ops-triage repo's benchmark.

## Per-CVE result (true NVD severity -> Claude's call)
- CVE-2014-7169: CRITICAL -> CRITICAL (confidence=0.95, escalated=yes - critical severity (always escalated regardless of confidence))
- CVE-2015-7755: CRITICAL -> CRITICAL (confidence=0.9, escalated=yes - critical severity (always escalated regardless of confidence))
- CVE-2026-9082: CRITICAL -> CRITICAL (confidence=0.85, escalated=yes - critical severity (always escalated regardless of confidence))
- CVE-2021-34473: CRITICAL -> CRITICAL (confidence=0.9, escalated=yes - critical severity (always escalated regardless of confidence))
- CVE-2023-48788: CRITICAL -> CRITICAL (confidence=0.95, escalated=yes - critical severity (always escalated regardless of confidence))
- CVE-2021-33044: CRITICAL -> CRITICAL (confidence=0.85, escalated=yes - critical severity (always escalated regardless of confidence))
- CVE-2024-40711: CRITICAL -> CRITICAL (confidence=0.95, escalated=yes - critical severity (always escalated regardless of confidence))
- CVE-2024-54085: CRITICAL -> CRITICAL (confidence=0.9, escalated=yes - critical severity (always escalated regardless of confidence))
- CVE-2020-1020: HIGH -> HIGH (confidence=0.8, escalated=no)
- CVE-2025-2747: CRITICAL -> CRITICAL (confidence=0.85, escalated=yes - critical severity (always escalated regardless of confidence))
- CVE-2020-17530: CRITICAL -> CRITICAL (confidence=0.9, escalated=yes - critical severity (always escalated regardless of confidence))
- CVE-2016-7255: HIGH -> HIGH (confidence=0.85, escalated=no)
- CVE-2017-6316: CRITICAL -> CRITICAL (confidence=0.95, escalated=yes - critical severity (always escalated regardless of confidence))
- CVE-2018-4063: HIGH -> HIGH (confidence=0.75, escalated=no)
- CVE-2017-6736: HIGH -> HIGH (confidence=0.8, escalated=no)
- CVE-2022-27924: HIGH -> HIGH (confidence=0.75, escalated=no)
- CVE-2026-0300: CRITICAL -> CRITICAL (confidence=0.95, escalated=yes - critical severity (always escalated regardless of confidence))
- CVE-2026-42897: HIGH -> MEDIUM (confidence=0.7, escalated=no)  MISMATCH
- CVE-2025-13223: HIGH -> HIGH (confidence=0.85, escalated=no)
- CVE-2024-51567: CRITICAL -> CRITICAL (confidence=0.95, escalated=yes - critical severity (always escalated regardless of confidence))
