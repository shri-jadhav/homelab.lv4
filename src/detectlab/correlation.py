
"""Correlation engine for incident grouping and chronological timeline reconstruction."""
from __future__ import annotations

from typing import Iterable

from .ingest import parse_timestamp
from .models import Alert, Incident, SecurityEvent, severity_rank


def group_incidents(
    alerts: Iterable[Alert],
    all_events: Iterable[SecurityEvent],
    correlation_window_hours: float = 4.0,
) -> list[Incident]:
    """Group correlated alerts into security incidents with event timelines."""
    alert_list = sorted(
        alerts,
        key=lambda alert: parse_timestamp(alert.first_seen),
    )
    if not alert_list:
        return []

    events_by_id: dict[str, SecurityEvent] = {
        event.event_id: event for event in all_events
    }

    clusters: list[list[Alert]] = []
    max_gap_seconds = correlation_window_hours * 3600

    for alert in alert_list:
        target_user = alert.context.get("user")
        target_ip = alert.context.get("source_ip")
        alert_start = parse_timestamp(alert.first_seen)
        alert_end = parse_timestamp(alert.last_seen)
        placed = False

        for cluster in clusters:
            cluster_starts = [
                parse_timestamp(item.first_seen) for item in cluster
            ]
            cluster_ends = [
                parse_timestamp(item.last_seen) for item in cluster
            ]
            cluster_min = min(cluster_starts)
            cluster_max = max(cluster_ends)

            time_distance = max(
                0.0,
                (alert_start - cluster_max).total_seconds(),
                (cluster_min - alert_end).total_seconds(),
            )

            if time_distance > max_gap_seconds:
                continue

            cluster_users = {
                item.context.get("user")
                for item in cluster
                if item.context.get("user")
            }
            cluster_ips = {
                item.context.get("source_ip")
                for item in cluster
                if item.context.get("source_ip")
            }
            cluster_rules = {item.rule_id for item in cluster}

            is_spray_campaign = (
                "DET-AUTH-002" in cluster_rules
                or alert.rule_id == "DET-AUTH-002"
            )

            user_match = bool(
                target_user and target_user in cluster_users
            )
            ip_match = bool(
                target_ip
                and target_ip != "unknown"
                and target_ip in cluster_ips
            )

            # Condition A: correlate alerts targeting the same user.
            if user_match:
                same_rule_burst = (
                    cluster_rules == {"DET-AUTH-001"}
                    and alert.rule_id == "DET-AUTH-001"
                )

                # Keep separate brute-force bursts apart.
                if same_rule_burst and time_distance > 10 * 60:
                    continue

                cluster.append(alert)
                placed = True
                break

            # Condition B: correlate multi-target password-spray campaigns.
            if ip_match and is_spray_campaign:
                cluster.append(alert)
                placed = True
                break

            # Condition C: correlate source-IP-only alerts with no known user.
            if ip_match and not target_user and not cluster_users:
                cluster.append(alert)
                placed = True
                break

        if not placed:
            clusters.append([alert])

    incidents: list[Incident] = []

    for idx, cluster in enumerate(clusters, start=1):
        cluster.sort(key=lambda item: parse_timestamp(item.first_seen))

        all_event_ids: list[str] = []
        seen_event_ids: set[str] = set()

        for alert in cluster:
            for event_id in alert.event_ids:
                if event_id not in seen_event_ids:
                    seen_event_ids.add(event_id)
                    all_event_ids.append(event_id)

        contributing_events = [
            events_by_id[event_id]
            for event_id in all_event_ids
            if event_id in events_by_id
        ]
        contributing_events.sort(key=lambda event: (event.dt, event.event_id))

        timeline = []
        for event in contributing_events:
            timeline.append(
                {
                    "timestamp": event.timestamp_str,
                    "event_id": event.event_id,
                    "host": event.host,
                    "event_type": event.event_type,
                    "user": event.user,
                    "source_ip": event.source_ip,
                    "outcome": event.outcome,
                    "description": _format_timeline_description(event),
                }
            )

        max_sev = max(
            (alert.severity for alert in cluster),
            key=severity_rank,
        )

        primary_entity = cluster[0].entity
        target_user = cluster[0].context.get("user")
        target_ip = cluster[0].context.get("source_ip")

        if target_user and target_ip:
            entity_label = f"User: {target_user} (Source: {target_ip})"
        elif target_user:
            entity_label = f"User: {target_user}"
        elif target_ip:
            entity_label = f"Source IP: {target_ip}"
        else:
            entity_label = primary_entity

        techniques = sorted(
            {
                technique
                for alert in cluster
                for technique in alert.mitre_attack
            }
        )
        tactics = sorted(
            {
                tactic
                for alert in cluster
                for tactic in alert.mitre_tactics
                if tactic
            }
        )

        summary_title, summary_narrative = _synthesize_incident_narrative(
            cluster,
            target_user,
            target_ip,
        )

        actions: list[str] = []
        seen_actions: set[str] = set()
        for alert in cluster:
            for action in alert.recommended_actions:
                clean_action = action.strip()
                if clean_action and clean_action not in seen_actions:
                    seen_actions.add(clean_action)
                    actions.append(clean_action)

        first_seen = (
            contributing_events[0].timestamp_str
            if contributing_events
            else cluster[0].first_seen
        )
        last_seen = (
            contributing_events[-1].timestamp_str
            if contributing_events
            else cluster[-1].last_seen
        )

        incident_date = (
            contributing_events[0].dt.strftime("%Y%m%d")
            if contributing_events
            else parse_timestamp(cluster[0].first_seen).strftime("%Y%m%d")
        )

        incident = Incident(
            incident_id=f"INC-{incident_date}-{idx:03d}",
            title=summary_title,
            severity=max_sev,
            status="open",
            entity=entity_label,
            first_seen=first_seen,
            last_seen=last_seen,
            alerts=cluster,
            mitre_attack=techniques,
            mitre_tactics=tactics,
            timeline=timeline,
            summary=summary_narrative,
            recommended_actions=actions,
        )
        incidents.append(incident)

    incidents.sort(
        key=lambda incident: (
            severity_rank(incident.severity),
            incident.first_seen,
        ),
        reverse=True,
    )
    return incidents


def _format_timeline_description(event: SecurityEvent) -> str:
    """Format a human-friendly timeline event description."""
    if event.event_type == "auth":
        outcome_str = (
            "SUCCEEDED"
            if event.outcome == "success"
            else f"FAILED ({event.outcome})"
        )
        return (
            f"Authentication {outcome_str} for '{event.user}' "
            f"from {event.source_ip} on {event.host} - "
            f"{event.message or 'No message'}"
        )

    if event.event_type == "privilege_change":
        role_info = (
            f"assigned role '{event.role}'"
            if event.role
            else "privilege modified"
        )
        ticket_info = f" (Ticket: {event.ticket_id})" if event.ticket_id else ""
        return (
            f"Privilege change: '{event.user}' {role_info} on {event.host}"
            f"{ticket_info} - {event.message or 'No message'}"
        )

    if event.event_type == "mfa_denial":
        return (
            f"MFA challenge REJECTED/DENIED for '{event.user}' on {event.host} - "
            f"{event.message or 'Push rejected by user'}"
        )

    return (
        f"Event {event.event_type} for '{event.user}' on {event.host}: "
        f"{event.message or 'Recorded'}"
    )


def _synthesize_incident_narrative(
    alerts: list[Alert],
    user: str | None,
    ip: str | None,
) -> tuple[str, str]:
    """Produce a concise SOC incident title and narrative."""
    rule_ids = {alert.rule_id for alert in alerts}

    if "DET-IAM-001" in rule_ids:
        title = f"Compromised Account and Privilege Escalation ({user or 'Target'})"
        description = (
            f"Multi-stage intrusion sequence detected for user '{user or 'unknown'}'. "
            "Activity progressed from repeated authentication failures to a successful "
            "login, immediately followed by an unauthorized or high-risk administrative "
            "role change."
        )
    elif "DET-AUTH-003" in rule_ids:
        title = f"Suspected Account Compromise via Password Guessing ({user or 'Target'})"
        description = (
            f"User account '{user or 'unknown'}' was successfully accessed after a "
            f"burst of authentication failures from source {ip or 'unknown'}, "
            "indicating credential exhaustion or guessing."
        )
    elif "DET-AUTH-002" in rule_ids:
        title = f"Password Spraying Campaign from {ip or 'Source'}"
        description = (
            f"External or unmanaged source {ip or 'unknown'} conducted horizontal "
            "password spraying against multiple distinct enterprise identities."
        )
    elif "DET-AUTH-004" in rule_ids:
        title = f"MFA Fatigue / Push Denial Anomaly ({user or 'Target'})"
        description = (
            f"Multiple repeated MFA push rejections were detected for user "
            f"'{user or 'unknown'}', suggesting prompt bombardment."
        )
    elif "DET-NET-001" in rule_ids:
        title = f"Distributed Credential Attack on {user or 'Target'}"
        description = (
            f"Account '{user or 'unknown'}' was targeted by authentication attempts "
            "originating from multiple distributed IP addresses."
        )
    else:
        title = f"Brute Force Authentication Burst ({user or 'Target'})"
        description = (
            f"Authentication failure volume exceeded anomaly thresholds for "
            f"'{user or 'unknown'}' originating from {ip or 'unknown'}."
        )

    return title, description
