# 🔵 Microsoft Sentinel - KQL Detection Lab

![Sentinel](https://img.shields.io/badge/Microsoft_Sentinel-SIEM-0078D4?style=flat&logo=microsoft)
![KQL](https://img.shields.io/badge/KQL-Query_Language-blue?style=flat)
![Azure](https://img.shields.io/badge/Azure-Cloud-0078D4?style=flat&logo=microsoftazure)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-red?style=flat)
![Blue Team](https://img.shields.io/badge/Blue_Team-Defensive-blue?style=flat)

> Microsoft Sentinel SIEM lab deployed in Azure - 5 KQL detection queries covering brute force attacks, external IP anomalies, SYSTEM account abuse, after-hours logons, and successful credential compromise. Includes a live automated Analytics Rule with MITRE ATT&CK mapping that generates incidents automatically.

---

## 🎯 Objective

Deploy Microsoft Sentinel in Azure, write production-grade KQL detection queries covering common attack patterns, and convert detections into automated Analytics Rules that generate actionable incidents - demonstrating end-to-end detection engineering workflow.

---

## 🔬 Environment

| Component | Detail |
|---|---|
| **Platform** | Microsoft Sentinel (Azure cloud) |
| **Workspace** | soc-lab-sentinel |
| **Query Language** | KQL (Kusto Query Language) |
| **Data Source** | Windows Security Events (SecurityEvent table) |
| **Analytics Rule** | Scheduled query - runs every 5 minutes, 15-minute lookback |

---

## 📋 Executive Summary

Deployed a Microsoft Sentinel workspace in Azure and authored 5 production-ready KQL detection rules covering common SOC Tier 1 alert scenarios. Converted the highest-priority detection into a live scheduled Analytics Rule that automatically generates HIGH severity incidents when brute force activity is detected. All detections include explicit time windows, IPv4/IPv6 filtering, and production tuning guidance. Queries are mapped to MITRE ATT&CK framework.

---

## 🔍 KQL Detection Queries

### Query 1 - Brute Force Detection (T1110)
**Description:** Flags accounts with 5+ failed logon attempts within 15 minutes - indicates password spray or brute force attack.

**Key Improvements:**
- Explicit 15-minute lookback window
- Filters empty accounts and loopback IPs
- Projects detection timestamp separately from event timestamps
- Includes tuning guidance for scanner exclusions

```kql
let Lookback = 15m;
let FailureThreshold = 5;

SecurityEvent
| where TimeGenerated >= ago(Lookback)
| where EventID == 4625
| where isnotempty(Account) and isnotempty(Computer)
| where IpAddress !in ("-", "", "127.0.0.1", "::1")
| summarize FailedAttempts = count(),
            FirstAttempt = min(TimeGenerated),
            LastAttempt = max(TimeGenerated)
    by Account, Computer, IpAddress
| where FailedAttempts >= FailureThreshold
| extend Severity = "HIGH"
| extend Description = strcat(
    "Possible brute force: ",
    tostring(FailedAttempts),
    " failed logons within ",
    tostring(Lookback)
)
| project TimeDetected = now(),
          Account,
          Computer,
          IpAddress,
          FailedAttempts,
          FirstAttempt,
          LastAttempt,
          Severity,
          Description
```

![Brute Force Detection](screenshots/kql-01-brute-force-detection.png)

**Production Tuning:**
- Exclude known vulnerability scanners by IP
- Exclude noisy service accounts
- Adjust threshold (3-10) based on environment baseline

---

### Query 2 - External IP Logon Anomaly (T1078)
**Description:** Flags successful or failed logons from non-private IPv4 addresses, excluding RFC1918, loopback, APIPA, and IPv6 link-local ranges.

**Key Improvements:**
- Uses native `ipv4_is_in_range()` function instead of regex
- Correctly handles 172.16.0.0/12 private range
- Includes IPv6 private range filtering
- Separates success and failure counts for better triage

```kql
let Lookback = 1h;

SecurityEvent
| where TimeGenerated >= ago(Lookback)
| where EventID in (4624, 4625)
| where isnotempty(IpAddress)
| where not(ipv4_is_in_range(IpAddress, "10.0.0.0/8"))
| where not(ipv4_is_in_range(IpAddress, "192.168.0.0/16"))
| where not(ipv4_is_in_range(IpAddress, "172.16.0.0/12"))
| where not(ipv4_is_in_range(IpAddress, "169.254.0.0/16"))
| where IpAddress !in ("127.0.0.1", "::1", "-", "")
| where not(IpAddress startswith "fe80:")
| where not(IpAddress startswith "fc00:")
| where not(IpAddress startswith "fd00:")
| summarize AttemptCount = count(),
            SuccessCount = countif(EventID == 4624),
            FailureCount = countif(EventID == 4625),
            FirstSeen = min(TimeGenerated),
            LastSeen = max(TimeGenerated)
    by Account, Computer, IpAddress
| extend Severity = iff(SuccessCount > 0, "HIGH", "MEDIUM")
| extend Description = iff(
    SuccessCount > 0,
    "Successful logon from external IP address",
    "Failed logon attempts from external IP address"
)
| project Account, Computer, IpAddress, AttemptCount, SuccessCount, FailureCount, FirstSeen, LastSeen, Severity, Description
```

![External IP Logon](screenshots/kql-02-external-ip-logon.png)

**Production Tuning:**
- Allowlist VPN egress IPs
- Allowlist cloud identity provider infrastructure (Okta, Azure AD)
- Allowlist known remote administration gateways

---

### Query 3 - SYSTEM Account Network Logon (T1078.003)
**Description:** Flags NT AUTHORITY\SYSTEM logons using network (Type 3) or remote interactive (Type 10) logon types - consistent with lateral movement or C2 activity.

**Key Improvements:**
- Exact match for `NT AUTHORITY\SYSTEM` (no partial matches)
- Excludes LogonType 5 (Service) to reduce false positives
- Provides context-specific descriptions for each LogonType

```kql
let Lookback = 1h;

SecurityEvent
| where TimeGenerated >= ago(Lookback)
| where EventID == 4624
| where Account =~ @"NT AUTHORITY\SYSTEM"
| where LogonType in (3, 10)
| where IpAddress !in ("-", "", "127.0.0.1", "::1")
| extend Severity = "HIGH"
| extend Description = case(
    LogonType == 3,  "SYSTEM network logon detected - review for lateral movement or remote service activity",
    LogonType == 10, "SYSTEM remote interactive logon detected - review for RDP abuse or session hijacking",
    "SYSTEM logon detected"
)
| project TimeGenerated, Account, Computer, IpAddress, LogonType, Severity, Description
```

![SYSTEM Account Logon](screenshots/kql-04-after-hours-logon.png)

**Production Tuning:**
- Exclude approved management tooling by source IP
- Exclude backup agents and remote admin platforms after validation
- LogonType 10 is rare for SYSTEM - investigate immediately

---

### Query 4 - Logon Outside Business Hours (T1078)
**Description:** Flags successful logons before 7AM or after 7PM UTC - supports insider threat and compromised credential detection.

**Key Improvements:**
- Explicit documentation that time evaluation is in UTC
- Excludes Windows system accounts (DWM, UMFD, machine accounts)
- Includes timezone context in alert description

```kql
let Lookback = 3d;
let BusinessStartHour = 7;   // 7 AM UTC
let BusinessEndHour = 19;    // 7 PM UTC

SecurityEvent
| where TimeGenerated >= ago(Lookback)
| where EventID == 4624
| where Account !contains "SYSTEM"
| where Account !startswith "DWM-"
| where Account !startswith "UMFD-"
| where Account !endswith "$"
| extend HourOfDay = datetime_part("hour", TimeGenerated)
| where HourOfDay < BusinessStartHour or HourOfDay >= BusinessEndHour
| extend Severity = "MEDIUM"
| extend Description = strcat(
    "Logon outside business hours at ",
    format_datetime(TimeGenerated, "yyyy-MM-dd HH:mm:ss"),
    " UTC (Hour: ", tostring(HourOfDay), ")"
)
| project TimeGenerated, Account, Computer, IpAddress, HourOfDay, Severity, Description
```

![After Hours Logon](screenshots/kql-04-after-hours-logon.png)

**Production Tuning:**
- Adjust business hours to match organizational timezone (convert UTC offset)
- Exclude approved after-hours users (on-call staff, shift workers)
- Exclude known batch jobs and scheduled tasks

---

### Query 5 - Successful Logon After Multiple Failures (T1110)
**Description:** Correlates repeated failed logons with a later successful logon from the same source within a defined time window - highest confidence indicator of successful credential compromise.

**Key Improvements:**
- Temporal correlation: success must occur AFTER failures
- 30-minute correlation window prevents false correlations
- Joins on Account+Computer+IpAddress for strict correlation
- Orders results by failure count and recency

```kql
let Lookback = 1h;
let FailureThreshold = 3;
let CorrelationWindow = 30m;

let FailedLogons =
    SecurityEvent
    | where TimeGenerated >= ago(Lookback)
    | where EventID == 4625
    | where IpAddress !in ("-", "", "127.0.0.1", "::1")
    | summarize FailCount = count(),
                FirstFail = min(TimeGenerated),
                LastFail = max(TimeGenerated)
        by Account, Computer, IpAddress
    | where FailCount >= FailureThreshold;

let SuccessfulLogons =
    SecurityEvent
    | where TimeGenerated >= ago(Lookback)
    | where EventID == 4624
    | where IpAddress !in ("-", "", "127.0.0.1", "::1")
    | project Account, Computer, IpAddress, SuccessTime = TimeGenerated;

SuccessfulLogons
| join kind=inner FailedLogons on Account, Computer, IpAddress
| where SuccessTime > LastFail
| where SuccessTime <= LastFail + CorrelationWindow
| summarize FirstSuccess = min(SuccessTime),
            LastSuccess = max(SuccessTime),
            SuccessCount = count(),
            FailCount = max(FailCount),
            FirstFail = min(FirstFail),
            LastFail = max(LastFail)
    by Account, Computer, IpAddress
| extend Severity = "CRITICAL"
| extend Description = strcat(
    "Successful logon from same source after ",
    tostring(FailCount),
    " failed attempts within ",
    tostring(CorrelationWindow),
    " - possible successful brute force"
)
| project FirstSuccess, LastSuccess, Account, Computer, IpAddress, SuccessCount, FailCount, FirstFail, LastFail, Severity, Description
| order by FailCount desc, LastSuccess desc
```

![Successful Brute Force](screenshots/kql-05-successful-brute-force.png)

**Production Tuning:**
- This version uses strict correlation (same Account+Computer+IP) for low false positives
- For broader detection, create separate query correlating on Account only (higher FP rate)
- Adjust correlation window (15m-1h) based on environment

---

## 🚨 Analytics Rule - Live Detection

Query 1 (Brute Force Detection) was converted into a scheduled Analytics Rule running every 5 minutes in Microsoft Sentinel. When triggered, it automatically generates a HIGH severity incident mapped to MITRE T1110.

| Setting | Value |
|---|---|
| **Rule name** | Brute Force Detection - Multiple Failed Logons |
| **Severity** | High |
| **Status** | Enabled |
| **Run frequency** | Every 5 minutes |
| **Lookback period** | 15 minutes |
| **Alert threshold** | More than 0 results |
| **Incident creation** | Enabled |
| **Entity mapping** | Account, Host, IP |
| **Alert grouping** | Group by matching entities |
| **Suppression** | 1 hour |
| **MITRE Tactic** | Credential Access |
| **MITRE Technique** | T1110 - Brute Force |

![Analytics Rule](screenshots/kql-06-analytics-rule.png)

**Why This Configuration:**
- 5-minute run frequency with 15-minute lookback ensures minimal alert delay
- Entity mapping enables automatic entity extraction for investigation
- Alert grouping by entities reduces duplicate incidents for same attack campaign
- 1-hour suppression prevents alert fatigue from repeated failures

---

## 🗺️ MITRE ATT&CK Mapping

| Query | Technique | ID |
|---|---|---|
| Brute Force Detection | Brute Force | T1110 |
| External IP Logon | Valid Accounts | T1078 |
| SYSTEM Account Logon | Valid Accounts: Local Accounts | T1078.003 |
| After Hours Logon | Valid Accounts | T1078 |
| Successful After Failures | Brute Force | T1110 |

---

## 🧪 Testing & Validation

Each query was tested in the `soc-lab-sentinel` workspace using simulated Windows Security Event logs.

| Query | Test Method | Initial Results | False Positives | Tuning Applied |
|---|---|---|---|---|
| **Brute Force** | Simulated failed logons | 12 alerts | 3 (scanner traffic) | Excluded loopback IPs |
| **External IP** | VPN and internet logons | 8 alerts | 2 (cloud identity provider) | Documented allowlist requirement |
| **SYSTEM Account** | Service logons | 47 alerts | 45 (LogonType 5) | Removed LogonType 5 from query |
| **After Hours** | Weekend logons | 23 alerts | 5 (machine accounts) | Excluded accounts ending with `$` |
| **Successful Brute Force** | Correlated events | 2 alerts | 0 | Temporal correlation working correctly |

**Key Findings:**
- **Query 3** originally included LogonType 5, which generated 45 false positives. Removing it reduced noise by 96%.
- **Query 2** RFC1918 filtering was initially incomplete (caught all 172.x addresses). Using `ipv4_is_in_range()` fixed this.
- **Query 5** temporal correlation prevented false matches where success occurred before failures.

---

## 🔵 SOC Analyst Workflow Demonstrated

1. **Detection Engineering**: Identify suspicious authentication patterns (failed logons, external IPs, SYSTEM abuse)
2. **Query Development**: Write KQL queries with proper time scoping and filtering
3. **Threshold Tuning**: Set thresholds (5 failures, 3d lookback) based on environment baseline
4. **False Positive Reduction**: Exclude known noisy sources (scanners, VPNs, service accounts)
5. **Temporal Correlation**: Link related events (failures → success) with time windows
6. **Automation**: Convert validated queries to scheduled Analytics Rules
7. **Incident Creation**: Enable automatic HIGH/CRITICAL severity incidents for Tier 1 triage
8. **Entity Mapping**: Extract Account, Host, IP for investigation playbooks

---

## 📁 Repository Structure

```
sentinel-kql-detection-lab/
├── README.md
├── queries/
│   ├── 01-brute-force-detection.kql
│   ├── 02-external-ip-logon.kql
│   ├── 03-system-account-logon.kql
│   ├── 04-after-hours-logon.kql
│   └── 05-successful-brute-force.kql
└── screenshots/
    ├── kql-01-brute-force-detection.png
    ├── kql-02-external-ip-logon.png
    ├── kql-04-after-hours-logon.png
    ├── kql-05-successful-brute-force.png
    └── kql-06-analytics-rule.png
```

---

## 🏅 Skills Demonstrated

- **Microsoft Sentinel**: Workspace deployment and configuration in Azure
- **KQL Query Language**: Advanced filtering, aggregation, correlation, and time-series analysis
- **Detection Engineering**: Converting threat intelligence to actionable detections
- **Temporal Logic**: Multi-query correlation using `let` statements and `join` operations
- **False Positive Reduction**: IP range filtering, account exclusions, LogonType scoping
- **Analytics Rule Creation**: Scheduled queries with entity mapping and alert grouping
- **MITRE ATT&CK**: Tactic and technique classification for threat coverage mapping
- **Production Readiness**: Tuning guidance, timezone handling, and testing documentation

---

## 🔗 Connect

**Built by Lovedip Singh**

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0077B5?style=flat&logo=linkedin)](https://linkedin.com/in/lovedip-singh-76802a1a3)
[![GitHub](https://img.shields.io/badge/GitHub-Follow-181717?style=flat&logo=github)](https://github.com/Lovedipsingh)

---

*This project demonstrates production-grade detection engineering skills for SOC Analyst and Detection Engineer roles. All queries include explicit time windows, comprehensive filtering, and production tuning guidance based on real-world SOC operations.*
