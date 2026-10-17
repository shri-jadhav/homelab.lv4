# Detection catalog

This lab contains four transparent, testable starter detections. Tune them against a representative baseline before production use.

| Rule ID | Detection | Logic | ATT&CK mapping | Important caveat |
|---|---|---|---|---|
| DET-AUTH-001 | Repeated authentication failures | 5+ failed authentications for one user from one source within 5 minutes | T1110 — Brute Force | NAT, shared egress, or test systems may create bursts |
| DET-AUTH-002 | Password spraying pattern | 8+ distinct users failed from one source within 10 minutes | T1110.003 — Password Spraying | Corporate proxies and identity providers may aggregate source IPs |
| DET-AUTH-003 | Successful login after repeated failures | Successful auth after 5+ failures for the same user/source within 10 minutes | T1110, T1078 — Valid Accounts | User may have mistyped a password; investigate MFA/device/session signals |
| DET-IAM-001 | Privilege change after suspicious authentication | Privilege change within 15 minutes of a successful login that followed repeated failures | T1098 — Account Manipulation | ATT&CK mapping is a hypothesis; verify what the specific role grant means in the environment |

## Event schema

Required fields: `event_id`, `timestamp`, `host`, `event_type`, `user`.

Supported event types: `auth`, `privilege_change`, `process_start`.

Optional fields used by detections include `source_ip`, `outcome`, `role`, and `message`. Timestamps should be ISO-8601; timezone-naive timestamps are treated as UTC in this lab. Every `event_id` must be unique.

## Engineering choices

- Rule logic is local and explainable; no external API calls or paid service required.
- Reports include the reason for firing, event IDs, severity, suggested validation steps, and ATT&CK technique identifiers.
- Synthetic test events are deliberately labelled in the narrative, not used as a detection feature.
- Severity is a triage hint, not a mathematical probability of compromise.
- ATT&CK mappings are analyst-authored starting points; check the technique description and context before claiming a confirmed mapping.
- Current version evaluates in-memory events and is intended for small lab datasets, not high-throughput streaming.
