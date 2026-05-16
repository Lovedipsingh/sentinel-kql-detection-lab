# Engineering Decisions

This document captures the rationale behind threshold choices, time windows, and tuning decisions in the detection logic. The goal is to show *why* — not just *what*.

---

## Why 5 failed attempts as the brute-force threshold?

Tested thresholds of 3, 5, and 10 against simulated failed-logon traffic. At 3, alert volume increased roughly 4x with only marginal lift in true-positive rate — most low-count failures were users mistyping passwords. At 10, the rule missed slower password-spray patterns. 5 is the inflection point where signal-to-noise improves measurably without losing coverage of patient attackers.

## Why a 15-minute lookback for the brute-force rule?

Aligned with the Analytics Rule's 5-minute run cadence to ensure overlap and prevent gaps. Short enough that bursty attacks don't get spread across multiple evaluations; long enough that paced attackers can't slip between windows.

## Why 30 minutes as the correlation window in Query 1?

Most observed brute-force-to-success sequences in public datasets (BOTSv3, simulated lab traffic) complete within 15–25 minutes. 30 minutes provides margin without introducing false correlations from unrelated activity — for example, a legitimate user logging in 45 minutes after mistyping their password earlier.

## Why exclude LogonType 5 from Query 4 instead of allowlisting service accounts?

Allowlisting specific service accounts requires environment-specific maintenance and doesn't generalize across deployments. LogonType-based exclusion catches the entire false-positive category structurally — service accounts authenticate as LogonType 5 by design, and that LogonType is benign for SYSTEM. This is the change that drove the 96% false-positive reduction documented in the README.

## Why use `ipv4_is_in_range()` instead of regex for private IP filtering?

The native function correctly handles the 172.16.0.0/12 range. A naive `startswith "172."` regex breaks this — 172.32.x.x is public but would be silently filtered. Cleaner, faster, and prevents coverage gaps.

## Why strict correlation (Account + Computer + IP) in Query 1 instead of Account only?

Strict correlation produces near-zero false positives at the cost of missing attacks that pivot source IPs mid-campaign. For Tier 1 SOC use where alert fatigue is a real cost, low FP rate wins. A broader Account-only variant could be deployed as a separate lower-severity detection to catch the IP-pivot case.

## Why HIGH severity for brute force and CRITICAL for successful-after-failures?

Brute force attempts are common and don't always indicate compromise. Successful logons *after* confirmed failures from the same source are the highest-confidence indicator of credential compromise in this rule set, justifying immediate Tier 2 escalation.

## Why a 1-hour suppression on the Analytics Rule?

Prevents alert fatigue from repeated failures within the same attack campaign while still allowing the rule to re-fire if activity resumes after a meaningful gap. Aligns with typical Tier 1 triage cycles where an incident is acknowledged and investigated before re-evaluation.

## Why 3-day lookback for the after-hours rule?

Off-hours access is rare enough that a wider window is needed to surface meaningful patterns. 3 days captures weekend activity and lets analysts see whether off-hours logons are a one-time event or a recurring pattern.
