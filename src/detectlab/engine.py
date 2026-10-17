"""Explainable SOC detection and correlation engine.

Processes normalized security telemetry against configurable detection rules,
generates explainable alert objects with MITRE ATT&CK mapping, and handles
time-window correlation, entity isolation, and deduplication.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from .ingest import normalize_event_dict, parse_timestamp
from .models import Alert, SecurityEvent, severity_rank
from .rules import DetectionConfig, RuleDefinition, get_default_rule_catalog


# Backwards-compatible legacy constants
FAILURE_THRESHOLD = 5
BRUTE_FORCE_WINDOW_MINUTES = 5
SPRAY_DISTINCT_USER_THRESHOLD = 8
SPRAY_WINDOW_MINUTES = 10
SUCCESS_AFTER_FAILURE_WINDOW_MINUTES = 10
PRIVILEGE_AFTER_SUSPICIOUS_AUTH_WINDOW_MINUTES = 15

# Backwards-compatible legacy RULES dictionary
RULES = {
    "DET-AUTH-001": {
        "title": "Repeated authentication failures",
        "severity": "medium",
        "attack": ["T1110"],
        "description": f"At least {FAILURE_THRESHOLD} failed authentications for the same user from the same source in {BRUTE_FORCE_WINDOW_MINUTES} minutes.",
        "threshold": f"{FAILURE_THRESHOLD} failures / {BRUTE_FORCE_WINDOW_MINUTES} minutes / same user + source IP",
    },
    "DET-AUTH-002": {
        "title": "Password spraying pattern",
        "severity": "high",
        "attack": ["T1110.003"],
        "description": f"At least {SPRAY_DISTINCT_USER_THRESHOLD} distinct user accounts fail authentication from one source within {SPRAY_WINDOW_MINUTES} minutes.",
        "threshold": f"{SPRAY_DISTINCT_USER_THRESHOLD} distinct users / {SPRAY_WINDOW_MINUTES} minutes / same source IP",
    },
    "DET-AUTH-003": {
        "title": "Successful login after repeated failures",
        "severity": "high",
        "attack": ["T1110", "T1078"],
        "description": f"A successful authentication follows at least {FAILURE_THRESHOLD} failures for the same user from the same source within {SUCCESS_AFTER_FAILURE_WINDOW_MINUTES} minutes.",
        "threshold": f"success within {SUCCESS_AFTER_FAILURE_WINDOW_MINUTES} minutes after {FAILURE_THRESHOLD}+ failures / same user + source IP",
    },
    "DET-IAM-001": {
        "title": "Privilege change after suspicious authentication",
        "severity": "critical",
        "attack": ["T1098"],
        "description": f"A privileged role change occurs within {PRIVILEGE_AFTER_SUSPICIOUS_AUTH_WINDOW_MINUTES} minutes of a suspicious login sequence for the same user.",
        "threshold": f"privilege change within {PRIVILEGE_AFTER_SUSPICIOUS_AUTH_WINDOW_MINUTES} minutes after suspicious authentication",
    },
}


def parse_time(value: str) -> datetime:
    """Parse ISO-8601 timestamps; naive timestamps are treated as UTC for lab repeatability."""
    return parse_timestamp(value)


def validate_events(events: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Validate and normalize raw input event dictionaries; fail closed on malformed records."""
    normalized: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    for line_no, raw in enumerate(events, start=1):
        if not isinstance(raw, dict):
            raise ValueError(f"Event #{line_no} must be a dictionary.")

        # Normalize via domain model to guarantee strict validation
        sec_event = normalize_event_dict(raw, line_no=line_no)

        if sec_event.event_id in seen_ids:
            raise ValueError(f"Input contains duplicate event_id values; event IDs must be unique ({sec_event.event_id}).")
        seen_ids.add(sec_event.event_id)

        # Retain backward-compatible dict structure with internal datetime
        e = sec_event.to_dict()
        e["_dt"] = sec_event.dt
        e["_sec_event"] = sec_event
        normalized.append(e)

    return sorted(normalized, key=lambda e: (e["_dt"], e["event_id"]))


class DetectionEngine:
    """Configurable SOC detection engine evaluating rules against security events."""

    def __init__(self, config: DetectionConfig | None = None) -> None:
        self.config = config or DetectionConfig()
        self.catalog = get_default_rule_catalog(self.config)

    def run(self, events: Iterable[SecurityEvent | dict[str, Any]]) -> list[Alert]:
        """Execute detection rules and return structured Alert objects."""
        # Normalize input to SecurityEvent objects
        sec_events: list[SecurityEvent] = []
        for item in events:
            if isinstance(item, SecurityEvent):
                sec_events.append(item)
            elif isinstance(item, dict):
                if "_sec_event" in item and isinstance(item["_sec_event"], SecurityEvent):
                    sec_events.append(item["_sec_event"])
                else:
                    sec_events.append(normalize_event_dict(item))
            else:
                raise TypeError(f"Expected SecurityEvent or dict, got {type(item)}")

        # Ensure events are sorted chronologically
        sec_events.sort(key=lambda e: (e.dt, e.event_id))

        raw_alerts: list[Alert] = []

        # Filter event subsets
        auth_failures = [e for e in sec_events if e.event_type == "auth" and e.outcome == "failure"]
        auth_successes = [e for e in sec_events if e.event_type == "auth" and e.outcome == "success"]
        privilege_changes = [e for e in sec_events if e.event_type == "privilege_change"]
        mfa_denials = [
            e for e in sec_events
            if e.event_type in {"mfa_denial", "auth"} and e.outcome in {"mfa_denied", "denied", "rejected"}
        ]

        # 1. DET-AUTH-001: Repeated authentication failures (Brute Force)
        if "DET-AUTH-001" in self.config.enabled_rules:
            raw_alerts.extend(self._detect_brute_force(auth_failures))

        # 2. DET-AUTH-002: Password spraying pattern
        if "DET-AUTH-002" in self.config.enabled_rules:
            raw_alerts.extend(self._detect_password_spraying(auth_failures))

        # 3. DET-AUTH-003: Successful login after repeated failures
        if "DET-AUTH-003" in self.config.enabled_rules:
            raw_alerts.extend(self._detect_success_after_failures(auth_failures, auth_successes))

        # 4. DET-IAM-001: Privilege change after suspicious authentication
        if "DET-IAM-001" in self.config.enabled_rules:
            raw_alerts.extend(self._detect_privilege_escalation(raw_alerts, privilege_changes, sec_events))

        # 5. DET-AUTH-004: MFA denial / fatigue anomaly
        if "DET-AUTH-004" in self.config.enabled_rules:
            raw_alerts.extend(self._detect_mfa_fatigue(mfa_denials))

        # 6. DET-NET-001: Distributed credential attack on single account
        if "DET-NET-001" in self.config.enabled_rules:
            raw_alerts.extend(self._detect_distributed_attack(auth_failures))

        # 7. DET-RECON-001: Suspicious local discovery / reconnaissance burst
        recon_events = [
            e for e in sec_events
            if e.event_type in {"reconnaissance", "process_start"}
            or e.extra.get("is_recon")
            or any(t in e.message.lower() for t in ["whoami", "net user", "net localgroup", "ipconfig", "systeminfo", "nltest"])
        ]
        if "DET-RECON-001" in self.config.enabled_rules and recon_events:
            raw_alerts.extend(self._detect_recon_burst(recon_events))

        # 8. DET-PERSIST-001: Suspicious or ephemeral scheduled task creation
        persist_events = [
            e for e in sec_events
            if e.event_type in {"persistence", "service_created", "task_created"}
            or e.extra.get("win_event_id") in {"4698", "7045"}
            or "scheduled task" in e.message.lower()
        ]
        if "DET-PERSIST-001" in self.config.enabled_rules and persist_events:
            raw_alerts.extend(self._detect_persistence(persist_events))

        # De-duplicate alerts across overlapping sliding windows
        deduped = self._deduplicate_alerts(raw_alerts)

        # Sort alerts: highest severity first, then chronologically by first_seen
        deduped.sort(key=lambda a: (severity_rank(a.severity), a.first_seen), reverse=True)
        return deduped

    def _create_alert(
        self,
        rule_id: str,
        events: list[SecurityEvent],
        entity: str,
        reason: str,
        first_dt: datetime,
        last_dt: datetime,
        extra_context: dict[str, Any] | None = None,
    ) -> Alert:
        rule = self.catalog[rule_id]
        context = dict(extra_context or {})
        evidence = [
            {
                "event_id": e.event_id,
                "timestamp": e.timestamp_str,
                "user": e.user,
                "source_ip": e.source_ip,
                "host": e.host,
                "outcome": e.outcome,
                "message": e.message,
            }
            for e in events
        ]

        return Alert(
            alert_id=f"{rule_id}-{events[-1].event_id}",
            rule_id=rule_id,
            title=rule.title,
            severity=rule.severity,
            status="new",
            entity=entity,
            first_seen=first_dt.isoformat().replace("+00:00", "Z"),
            last_seen=last_dt.isoformat().replace("+00:00", "Z"),
            event_count=len(events),
            event_ids=[e.event_id for e in events],
            mitre_attack=list(rule.mitre_attack),
            mitre_tactics=list(rule.mitre_tactics),
            why_it_fired=reason,
            rule_threshold=rule.threshold,
            recommended_actions=list(rule.recommended_actions),
            evidence=evidence,
            context=context,
        )

    def _detect_brute_force(self, auth_failures: list[SecurityEvent]) -> list[Alert]:
        alerts: list[Alert] = []
        thresh = self.config.brute_force_failure_threshold
        win_delta = timedelta(minutes=self.config.brute_force_window_minutes)

        # Group by (source_ip, user)
        grouped: dict[tuple[str, str], list[SecurityEvent]] = defaultdict(list)
        for e in auth_failures:
            # Ignore events where both user and source_ip are completely unknown
            if (not e.user or e.user == "unknown") and (not e.source_ip or e.source_ip == "unknown"):
                continue
            grouped[(e.source_ip, e.user)].append(e)

        for (ip, user), group in grouped.items():
            idx = 0
            while idx < len(group):
                start_dt = group[idx].dt
                window = [e for e in group[idx:] if e.dt <= start_dt + win_delta]
                if len(window) >= thresh:
                    alerts.append(self._create_alert(
                        rule_id="DET-AUTH-001",
                        events=window,
                        entity=f"user={user}; source_ip={ip}",
                        reason=(
                            f"Observed {len(window)} failed authentications for user '{user}' from {ip} "
                            f"within {self.config.brute_force_window_minutes} minutes; threshold is {thresh}."
                        ),
                        first_dt=window[0].dt,
                        last_dt=window[-1].dt,
                        extra_context={"source_ip": ip, "user": user},
                    ))
                    # Advance index past this window to allow subsequent independent bursts
                    idx += len(window)
                else:
                    idx += 1

        return alerts

    def _detect_password_spraying(self, auth_failures: list[SecurityEvent]) -> list[Alert]:
        alerts: list[Alert] = []
        thresh = self.config.spray_distinct_user_threshold
        win_delta = timedelta(minutes=self.config.spray_window_minutes)

        # Group by source_ip
        grouped: dict[str, list[SecurityEvent]] = defaultdict(list)
        for e in auth_failures:
            # Skip failures with unknown/empty source IP to prevent false cross-enterprise correlation
            if not e.source_ip or e.source_ip == "unknown":
                continue
            grouped[e.source_ip].append(e)

        for ip, group in grouped.items():
            idx = 0
            while idx < len(group):
                start_dt = group[idx].dt
                window = [e for e in group[idx:] if e.dt <= start_dt + win_delta]
                distinct_users = sorted({e.user for e in window})
                if len(distinct_users) >= thresh:
                    alerts.append(self._create_alert(
                        rule_id="DET-AUTH-002",
                        events=window,
                        entity=f"source_ip={ip}",
                        reason=(
                            f"Source {ip} failed authentication for {len(distinct_users)} distinct users "
                            f"in {self.config.spray_window_minutes} minutes; threshold is {thresh}."
                        ),
                        first_dt=window[0].dt,
                        last_dt=window[-1].dt,
                        extra_context={"source_ip": ip, "targeted_users": distinct_users},
                    ))
                    idx += len(window)
                else:
                    idx += 1

        return alerts

    def _detect_success_after_failures(
        self,
        auth_failures: list[SecurityEvent],
        auth_successes: list[SecurityEvent],
    ) -> list[Alert]:
        alerts: list[Alert] = []
        thresh = self.config.brute_force_failure_threshold
        win_delta = timedelta(minutes=self.config.success_after_failure_window_minutes)

        consumed_failure_ids: set[str] = set()

        for success in auth_successes:
            ip, user, succ_dt = success.source_ip, success.user, success.dt
            prior = [
                e for e in auth_failures
                if e.source_ip == ip and e.user == user
                and timedelta(0) <= (succ_dt - e.dt) <= win_delta
                and e.event_id not in consumed_failure_ids
            ]
            if len(prior) >= thresh:
                seq = prior + [success]
                for p in prior:
                    consumed_failure_ids.add(p.event_id)

                alerts.append(self._create_alert(
                    rule_id="DET-AUTH-003",
                    events=seq,
                    entity=f"user={user}; source_ip={ip}",
                    reason=(
                        f"A successful login for '{user}' from {ip} followed {len(prior)} failures "
                        f"within {self.config.success_after_failure_window_minutes} minutes."
                    ),
                    first_dt=prior[0].dt,
                    last_dt=succ_dt,
                    extra_context={"source_ip": ip, "user": user},
                ))

        return alerts

    def _detect_privilege_escalation(
        self,
        prior_alerts: list[Alert],
        privilege_changes: list[SecurityEvent],
        all_events: list[SecurityEvent],
    ) -> list[Alert]:
        alerts: list[Alert] = []
        win_delta = timedelta(minutes=self.config.privilege_after_auth_window_minutes)
        events_by_id = {e.event_id: e for e in all_events}

        for change in privilege_changes:
            user = change.user
            change_dt = change.dt

            # Benign control check: if change is authorized with ticket or explicit approval
            if self.config.suppress_approved_privilege_changes and (change.approved or change.ticket_id):
                continue

            # Look for related DET-AUTH-003 alert for this user
            related_alerts = [
                a for a in prior_alerts
                if a.rule_id == "DET-AUTH-003" and a.context.get("user") == user
                and timedelta(0) <= (change_dt - parse_timestamp(a.last_seen)) <= win_delta
            ]

            if related_alerts:
                base_alert = related_alerts[-1]
                contributing_events = [events_by_id[eid] for eid in base_alert.event_ids if eid in events_by_id]
                contributing_events.append(change)

                alerts.append(self._create_alert(
                    rule_id="DET-IAM-001",
                    events=contributing_events,
                    entity=f"user={user}; host={change.host}",
                    reason=(
                        f"Privilege change to '{change.role or 'unspecified role'}' for '{user}' occurred "
                        f"within {self.config.privilege_after_auth_window_minutes} minutes of a successful "
                        "login following repeated failures."
                    ),
                    first_dt=contributing_events[0].dt,
                    last_dt=change_dt,
                    extra_context={
                        "user": user,
                        "host": change.host,
                        "role_granted": change.role,
                        "ticket_id": change.ticket_id,
                    },
                ))

        return alerts

    def _detect_mfa_fatigue(self, mfa_denials: list[SecurityEvent]) -> list[Alert]:
        alerts: list[Alert] = []
        thresh = self.config.mfa_denial_threshold
        win_delta = timedelta(minutes=self.config.mfa_window_minutes)

        grouped: dict[str, list[SecurityEvent]] = defaultdict(list)
        for e in mfa_denials:
            grouped[e.user].append(e)

        for user, group in grouped.items():
            idx = 0
            while idx < len(group):
                start_dt = group[idx].dt
                window = [e for e in group[idx:] if e.dt <= start_dt + win_delta]
                if len(window) >= thresh:
                    alerts.append(self._create_alert(
                        rule_id="DET-AUTH-004",
                        events=window,
                        entity=f"user={user}",
                        reason=(
                            f"Detected {len(window)} MFA challenge denials for user '{user}' within "
                            f"{self.config.mfa_window_minutes} minutes (MFA fatigue / prompt-bombing indicator)."
                        ),
                        first_dt=window[0].dt,
                        last_dt=window[-1].dt,
                        extra_context={"user": user, "mfa_denials": len(window)},
                    ))
                    idx += len(window)
                else:
                    idx += 1

        return alerts

    def _detect_distributed_attack(self, auth_failures: list[SecurityEvent]) -> list[Alert]:
        alerts: list[Alert] = []
        thresh = self.config.distributed_source_threshold
        win_delta = timedelta(minutes=self.config.distributed_window_minutes)

        grouped: dict[str, list[SecurityEvent]] = defaultdict(list)
        for e in auth_failures:
            grouped[e.user].append(e)

        for user, group in grouped.items():
            idx = 0
            while idx < len(group):
                start_dt = group[idx].dt
                window = [e for e in group[idx:] if e.dt <= start_dt + win_delta]
                distinct_ips = sorted({e.source_ip for e in window if e.source_ip and e.source_ip != "unknown"})
                if len(distinct_ips) >= thresh:
                    alerts.append(self._create_alert(
                        rule_id="DET-NET-001",
                        events=window,
                        entity=f"user={user}",
                        reason=(
                            f"User '{user}' targeted by authentication failures from {len(distinct_ips)} distinct "
                            f"source IPs within {self.config.distributed_window_minutes} minutes."
                        ),
                        first_dt=window[0].dt,
                        last_dt=window[-1].dt,
                        extra_context={"user": user, "source_ips": distinct_ips},
                    ))
                    idx += len(window)
                else:
                    idx += 1

        return alerts

    def _detect_recon_burst(self, recon_events: list[SecurityEvent]) -> list[Alert]:
        alerts: list[Alert] = []
        thresh = self.config.recon_burst_threshold
        win_delta = timedelta(minutes=self.config.recon_window_minutes)

        # Group by (host, user)
        grouped: dict[tuple[str, str], list[SecurityEvent]] = defaultdict(list)
        for e in recon_events:
            grouped[(e.host, e.user)].append(e)

        for (host, user), group in grouped.items():
            idx = 0
            while idx < len(group):
                start_dt = group[idx].dt
                window = [e for e in group[idx:] if e.dt <= start_dt + win_delta]
                if len(window) >= thresh:
                    alerts.append(self._create_alert(
                        rule_id="DET-RECON-001",
                        events=window,
                        entity=f"host={host}; user={user}",
                        reason=(
                            f"Observed {len(window)} rapid system discovery activities on host '{host}' by '{user}' "
                            f"within {self.config.recon_window_minutes} minutes; threshold is {thresh}."
                        ),
                        first_dt=window[0].dt,
                        last_dt=window[-1].dt,
                        extra_context={"host": host, "user": user, "recon_commands": [e.message for e in window]},
                    ))
                    idx += len(window)
                else:
                    idx += 1

        return alerts

    def _detect_persistence(self, persist_events: list[SecurityEvent]) -> list[Alert]:
        alerts: list[Alert] = []
        for e in persist_events:
            alerts.append(self._create_alert(
                rule_id="DET-PERSIST-001",
                events=[e],
                entity=f"host={e.host}; user={e.user}",
                reason=f"Scheduled task / persistence modification detected: {e.message or e.event_id}",
                first_dt=e.dt,
                last_dt=e.dt,
                extra_context={"host": e.host, "user": e.user, "details": e.message},
            ))
        return alerts

    def _deduplicate_alerts(self, alerts: list[Alert]) -> list[Alert]:
        """Deduplicate overlapping alert occurrences while preserving distinct time windows."""
        if not alerts:
            return []

        by_rule_entity: dict[tuple[str, str], list[Alert]] = defaultdict(list)
        for a in alerts:
            by_rule_entity[(a.rule_id, a.entity)].append(a)

        deduped: list[Alert] = []
        for (rule_id, entity), candidate_alerts in by_rule_entity.items():
            candidate_alerts.sort(key=lambda a: (parse_timestamp(a.first_seen), -a.event_count))
            merged_for_group: list[Alert] = []

            for current in candidate_alerts:
                curr_start = parse_timestamp(current.first_seen)
                curr_end = parse_timestamp(current.last_seen)
                curr_eids = set(current.event_ids)

                overlap_found = False
                for i, existing in enumerate(merged_for_group):
                    ex_start = parse_timestamp(existing.first_seen)
                    ex_end = parse_timestamp(existing.last_seen)
                    ex_eids = set(existing.event_ids)

                    is_overlapping = not (curr_end < ex_start or curr_start > ex_end) or bool(curr_eids & ex_eids)
                    if is_overlapping:
                        overlap_found = True
                        if current.event_count > existing.event_count or curr_eids.issuperset(ex_eids):
                            merged_for_group[i] = current
                        break

                if not overlap_found:
                    merged_for_group.append(current)

            deduped.extend(merged_for_group)

        return deduped


def detect(
    events: Iterable[dict[str, Any] | SecurityEvent],
    config: DetectionConfig | None = None,
) -> list[dict[str, Any]]:
    """Legacy-compatible detection function returning list of alert dictionaries."""
    engine = DetectionEngine(config=config)
    alerts = engine.run(events)
    return [a.to_dict() for a in alerts]
