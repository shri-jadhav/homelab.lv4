# MITRE ATT&CK Detection Coverage Matrix

This report maps the SOC Detection Engineering Lab rules to the [MITRE ATT&CK Framework](https://attack.mitre.org/).

## Coverage Summary

- **Active Detection Rules:** 6
- **ATT&CK Tactics Covered:** 4 of 4 mapped
- **ATT&CK Techniques / Sub-techniques:** 6 mapped

## MITRE ATT&CK Tactics Alignment

| Tactic ID | Tactic Name | Detection Rules | Description |
|---|---|---|---|
| TA0006 | **Credential Access** | `DET-AUTH-001`, `DET-AUTH-002`, `DET-AUTH-003`, `DET-AUTH-004`, `DET-NET-001` | Techniques for stealing credentials like account names and passwords. |
| TA0001 | **Initial Access** | `DET-AUTH-003` | Techniques that use various entry vectors to gain an initial foothold. |
| TA0003 | **Persistence** | `DET-AUTH-003`, `DET-IAM-001` | Techniques that adversaries use to keep access across restarts and changed credentials. |
| TA0004 | **Privilege Escalation** | `DET-IAM-001` | Techniques that adversaries use to gain higher-level permissions. |

## MITRE ATT&CK Techniques Alignment

| Technique ID | Technique Name | Primary Tactic | Detection Rules | Reference |
|---|---|---|---|---|
| `T1078` | Valid Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access | `DET-AUTH-003` | [MITRE Page](https://attack.mitre.org/techniques/T1078/) |
| `T1098` | Account Manipulation | Persistence, Privilege Escalation | `DET-IAM-001` | [MITRE Page](https://attack.mitre.org/techniques/T1098/) |
| `T1110` | Brute Force | Credential Access | `DET-AUTH-001`, `DET-AUTH-003` | [MITRE Page](https://attack.mitre.org/techniques/T1110/) |
| `T1110.003` | Password Spraying | Credential Access | `DET-AUTH-002` | [MITRE Page](https://attack.mitre.org/techniques/T1110/003/) |
| `T1110.004` | Credential Stuffing | Credential Access | `DET-NET-001` | [MITRE Page](https://attack.mitre.org/techniques/T1110/004/) |
| `T1621` | Multi-Factor Authentication Request Generation | Credential Access | `DET-AUTH-004` | [MITRE Page](https://attack.mitre.org/techniques/T1621/) |

## Complete Detection Catalog & Thresholds

| Rule ID | Title | Severity | Configured Threshold | ATT&CK Mapping | Test Status |
|---|---|---|---|---|---|
| `DET-AUTH-001` | **Repeated authentication failures** | `MEDIUM` | 5 failures / 5 minutes / same user + source IP | `T1110` | Verified (Unit & Benchmark Tested) |
| `DET-AUTH-002` | **Password spraying pattern** | `HIGH` | 8 distinct users / 10 minutes / same source IP | `T1110.003` | Verified (Unit & Benchmark Tested) |
| `DET-AUTH-003` | **Successful login after repeated failures** | `HIGH` | success within 10 minutes after 5+ failures / same user + source IP | `T1110`, `T1078` | Verified (Unit & Benchmark Tested) |
| `DET-AUTH-004` | **Multi-Factor Authentication (MFA) denial anomaly** | `HIGH` | 2 MFA denials / 10 minutes / same user | `T1621` | Verified (Unit & Benchmark Tested) |
| `DET-IAM-001` | **Privilege change after suspicious authentication** | `CRITICAL` | privilege change within 15 minutes after suspicious authentication | `T1098` | Verified (Unit & Benchmark Tested) |
| `DET-NET-001` | **Distributed credential attack on single account** | `HIGH` | 4 distinct source IPs / 15 minutes / same user | `T1110.004` | Verified (Unit & Benchmark Tested) |

## Operational Context & Real-World Limitations

> [!IMPORTANT]
> **Synthetic Test Coverage vs. Real-World Effectiveness:**
> The test suite confirms that detection logic accurately processes expected synthetic event structures and thresholds.
> In operational environments, detection engineering requires:
> 1. **Baseline Telemetry Auditing:** Ensuring authentication logs reliably record source IP, user-agent, and failure reason codes (e.g. Windows Event 4625 sub-status codes 0xC000006A vs 0xC0000064).
> 2. **Allowlist Tuning:** Accounting for legitimate batch jobs, vulnerability scanners, and corporate VPN egress gateways.
> 3. **Context Enrichment:** Correlating directory roles, user VIP status, and GeoIP velocity.
