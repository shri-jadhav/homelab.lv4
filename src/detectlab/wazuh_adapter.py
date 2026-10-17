"""Wazuh SIEM alert adapter.

Imports and normalizes genuine Wazuh alerts from /var/ossec/logs/alerts/alerts.json
into standardized SecurityEvent instances for the detectlab correlation engine,
while preserving the exact underlying raw evidence.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .ingest import parse_timestamp
from .models import IngestionReport, SecurityEvent


def map_wazuh_alert_to_event(raw: dict[str, Any], event_index: int = 1) -> SecurityEvent:
    """Normalize a Wazuh alert dictionary into a SecurityEvent instance."""
    # 1. Timestamp extraction - do not fabricate fallback dates
    ts_str = (
        raw.get("timestamp")
        or raw.get("@timestamp")
        or raw.get("data", {}).get("win", {}).get("system", {}).get("systemTime")
    )
    if not ts_str:
        raise ValueError(f"Wazuh alert (index {event_index}) is missing a valid timestamp.")
    dt = parse_timestamp(ts_str)

    # 2. Host extraction
    agent = raw.get("agent", {})
    win_system = raw.get("data", {}).get("win", {}).get("system", {})
    host = win_system.get("computer") or agent.get("name") or agent.get("id") or "wazuh-agent"

    # 3. Windows Event ID & Event Type mapping
    win_data = raw.get("data", {}).get("win", {})
    event_data = win_data.get("eventdata", {})
    win_event_id = str(win_system.get("eventID") or raw.get("data", {}).get("event_id") or "").strip()

    rule = raw.get("rule", {})
    rule_desc = rule.get("description", "")
    rule_id = str(rule.get("id", "")).strip()

    raw_user = (
        event_data.get("targetUserName")
        or event_data.get("targetAccountName")
        or event_data.get("subjectUserName")
        or raw.get("data", {}).get("user")
        or "SYSTEM"
    )
    user = str(raw_user).strip() if raw_user and raw_user != "-" else "SYSTEM"

    raw_ip = (
        event_data.get("ipAddress")
        or event_data.get("sourceIp")
        or raw.get("data", {}).get("srcip")
        or ""
    )
    raw_ip_str = str(raw_ip).strip()
    source_ip = raw_ip_str if raw_ip_str and raw_ip_str != "-" else "unknown"

    # Classify event_type and outcome strictly without broad substring false positives
    rule_desc_lower = rule_desc.lower()
    if (
        win_event_id == "4625"
        or rule_id in {"60122", "60204"}
        or "logon failure" in rule_desc_lower
        or "authentication failed" in rule_desc_lower
    ):
        event_type = "auth"
        outcome = "failure"
        message = f"Wazuh Rule {rule_id}: {rule_desc} (EventID: 4625)"
        role = ""
    elif (
        win_event_id == "4624"
        or rule_id in {"60106"}
        or "logon success" in rule_desc_lower
        or "authentication success" in rule_desc_lower
        or "account was successfully logged on" in rule_desc_lower
    ):
        event_type = "auth"
        outcome = "success"
        message = f"Wazuh Rule {rule_id}: {rule_desc} (EventID: 4624)"
        role = ""
    elif (
        win_event_id in {"4728", "4732", "4756"}
        or rule_id in {"60114"}
        or (win_event_id == "4672" and "privilege" in rule_desc_lower)
        or "user added to privileged" in rule_desc_lower
        or "group member added" in rule_desc_lower
    ):
        event_type = "privilege_change"
        outcome = "success"
        member = event_data.get("memberName") or event_data.get("targetUserName") or user
        target_group = event_data.get("targetUserName") or "PrivilegedGroup"
        role = str(target_group)
        message = f"Wazuh Rule {rule_id}: Member '{member}' added to '{target_group}' (EventID: {win_event_id})"
    elif (
        win_event_id in {"4688", "1"}
        or "process created" in rule_desc_lower
        or "process started" in rule_desc_lower
    ):
        event_type = "process_start"
        outcome = "success"
        role = ""
        message = f"Wazuh Rule {rule_id}: {rule_desc}"
    else:
        # Generic system, SCA, application, or audit events are categorized as 'system'
        event_type = "system"
        outcome = "info"
        role = ""
        message = f"Wazuh Rule {rule_id}: {rule_desc}"

    event_id = f"WAZUH-{raw.get('id', f'E{event_index:04d}')}"

    # Preserve exact raw Wazuh alert in extra dictionary
    extra = {
        "wazuh_rule_id": rule_id,
        "wazuh_rule_level": rule.get("level"),
        "wazuh_agent_name": agent.get("name"),
        "wazuh_agent_ip": agent.get("ip"),
        "win_event_id": win_event_id,
        "raw_wazuh_alert": raw,
    }

    return SecurityEvent(
        event_id=event_id,
        timestamp_str=dt.isoformat().replace("+00:00", "Z"),
        dt=dt,
        host=host,
        event_type=event_type,
        user=user,
        source_ip=source_ip,
        outcome=outcome,
        role=role,
        message=message,
        extra=extra,
    )


def load_wazuh_alerts(file_path: Path | str, strict: bool = False) -> tuple[list[SecurityEvent], IngestionReport]:
    """Read a Wazuh alerts.json file and return normalized SecurityEvent objects and diagnostics."""
    path = Path(file_path)
    events: list[SecurityEvent] = []
    report = IngestionReport()

    with path.open("r", encoding="utf-8-sig") as handle:
        for idx, line in enumerate(handle, start=1):
            report.total_lines += 1
            line_str = line.strip()
            if not line_str or line_str.startswith("#"):
                report.dropped_empty_or_comments += 1
                continue
            try:
                alert_dict = json.loads(line_str)
            except json.JSONDecodeError as exc:
                err = f"Line {idx}: Invalid JSON in Wazuh alert record: {exc}"
                report.errors.append(err)
                report.quarantined_events += 1
                report.quarantined_records.append({"line_number": idx, "raw": line_str, "reason": err})
                if strict:
                    raise ValueError(err) from exc
                continue

            if not isinstance(alert_dict, dict):
                err = f"Line {idx}: Wazuh alert record must be a JSON object"
                report.errors.append(err)
                report.quarantined_events += 1
                report.quarantined_records.append({"line_number": idx, "raw": alert_dict, "reason": err})
                if strict:
                    raise ValueError(err)
                continue

            try:
                event = map_wazuh_alert_to_event(alert_dict, event_index=idx)
                events.append(event)
                report.valid_events += 1
            except ValueError as exc:
                err = f"Line {idx}: {exc}"
                report.errors.append(err)
                report.quarantined_events += 1
                report.quarantined_records.append({"line_number": idx, "raw": alert_dict, "reason": err})
                if strict:
                    raise exc
                continue

    events.sort(key=lambda e: (e.dt, e.event_id))
    return events, report
