"""Robust JSONL ingestion, schema validation, and timestamp normalization."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .models import IngestionReport, SecurityEvent

SUPPORTED_EVENT_TYPES = {
    "auth",
    "privilege_change",
    "process_start",
    "mfa_challenge",
    "mfa_denial",
    "network_connection",
    "persistence",
    "reconnaissance",
    "task_created",
    "service_created",
    "log_cleared",
    "system",
}

REQUIRED_FIELDS = {"event_id", "timestamp", "host", "event_type", "user"}


def parse_timestamp(value: Any) -> datetime:
    """Parse various timestamp representations into a timezone-aware UTC datetime.
    
    Supports:
    - ISO 8601 strings with Z or offset (e.g., 2026-10-16T09:00:00Z, +05:30, -04:00)
    - Naive ISO strings (assumed UTC for reproducible testing)
    - Space-separated ISO strings (e.g., 2026-10-16 09:00:00)
    - Numeric Unix epoch timestamps (seconds or milliseconds)
    """
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    if isinstance(value, (int, float)):
        # If timestamp is > 10^11, likely milliseconds
        if value > 1e11:
            value = value / 1000.0
        return datetime.fromtimestamp(value, tz=timezone.utc)

    val_str = str(value).strip()
    if not val_str:
        raise ValueError("Timestamp value cannot be empty.")

    # Standardize 'Z' to '+00:00' for fromisoformat compatibility
    val_str = val_str.replace("Z", "+00:00").replace("z", "+00:00")
    
    # Try ISO fromisoformat
    try:
        dt = datetime.fromisoformat(val_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (ValueError, TypeError):
        pass

    # Try common fallback patterns
    formats = [
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%d",
    ]
    for fmt in formats:
        try:
            dt = datetime.strptime(val_str, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except (ValueError, TypeError):
            continue

    raise ValueError(f"Unable to parse timestamp: {value!r}")


def normalize_event_dict(raw: dict[str, Any], line_no: int = 0) -> SecurityEvent:
    """Validate and normalize a raw event dictionary into a SecurityEvent instance."""
    if not isinstance(raw, dict):
        raise ValueError(f"Line {line_no}: Event record must be a JSON object / dict.")

    # Handle common field aliases
    user = raw.get("user") or raw.get("username") or raw.get("account")
    source_ip = raw.get("source_ip") or raw.get("src_ip") or raw.get("ip") or "unknown"
    outcome = raw.get("outcome") or raw.get("status") or raw.get("result") or "unknown"
    host = raw.get("host") or raw.get("hostname") or raw.get("computer_name")
    event_type = raw.get("event_type") or raw.get("type")
    event_id = raw.get("event_id") or raw.get("id")
    timestamp = raw.get("timestamp") or raw.get("time") or raw.get("@timestamp")

    synthetic_raw = {
        "event_id": event_id,
        "timestamp": timestamp,
        "host": host,
        "event_type": event_type,
        "user": user,
    }
    missing = [k for k, v in synthetic_raw.items() if v is None or str(v).strip() == ""]
    if missing:
        prefix = f"Line {line_no}: " if line_no > 0 else ""
        raise ValueError(f"{prefix}Event is missing required field(s): {', '.join(sorted(missing))}")

    event_id_str = str(event_id).strip()
    event_type_str = str(event_type).strip()
    if event_type_str not in SUPPORTED_EVENT_TYPES:
        raise ValueError(f"Event {event_id_str} has unsupported event_type: {event_type_str}")

    dt = parse_timestamp(timestamp)
    timestamp_iso = dt.isoformat().replace("+00:00", "Z")

    # Extract optional metadata
    role = str(raw.get("role", "")).strip()
    message = str(raw.get("message", "")).strip()
    ticket_id = str(raw.get("ticket_id", "")).strip()
    approved = bool(raw.get("approved", False))

    known_keys = {
        "event_id", "timestamp", "host", "event_type", "user", "source_ip",
        "outcome", "role", "message", "ticket_id", "approved", "username",
        "src_ip", "status", "result", "type", "id", "hostname", "@timestamp"
    }
    extra = {k: v for k, v in raw.items() if k not in known_keys}

    return SecurityEvent(
        event_id=event_id_str,
        timestamp_str=timestamp_iso,
        dt=dt,
        host=str(host).strip(),
        event_type=event_type_str,
        user=str(user).strip(),
        source_ip=str(source_ip).strip(),
        outcome=str(outcome).strip().lower(),
        role=role,
        message=message,
        ticket_id=ticket_id,
        approved=approved,
        extra=extra,
    )


def load_events_from_jsonl(path: Path | str, strict: bool = False) -> tuple[list[SecurityEvent], IngestionReport]:
    """Load JSONL events with detailed ingestion diagnostics.
    
    If strict=True:
        Fails fast on any JSON decode error, missing field, bad type, or duplicate event_id.
    If strict=False:
        Quarantines invalid and duplicate records into IngestionReport, allowing valid
        events to proceed without halting SOC analysis.
    """
    file_path = Path(path)
    report = IngestionReport()
    valid_events: list[SecurityEvent] = []
    seen_ids: set[str] = set()

    with file_path.open("r", encoding="utf-8-sig") as handle:
        for line_no, line in enumerate(handle, start=1):
            report.total_lines += 1
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                report.dropped_empty_or_comments += 1
                continue

            try:
                raw = json.loads(stripped)
            except json.JSONDecodeError as exc:
                err = f"Invalid JSON on line {line_no}: {exc}"
                report.errors.append(err)
                report.quarantined_events += 1
                report.quarantined_records.append({"line_number": line_no, "raw": stripped, "reason": err})
                if strict:
                    raise ValueError(err) from exc
                continue

            try:
                event = normalize_event_dict(raw, line_no=line_no)
            except ValueError as exc:
                err = str(exc)
                report.errors.append(err)
                report.quarantined_events += 1
                report.quarantined_records.append({"line_number": line_no, "raw": raw, "reason": err})
                if strict:
                    raise exc
                continue

            # Check duplicate ID
            if event.event_id in seen_ids:
                err = f"Duplicate event_id '{event.event_id}' encountered at line {line_no}."
                report.duplicate_events += 1
                report.quarantined_events += 1
                report.errors.append(err)
                report.quarantined_records.append({"line_number": line_no, "raw": raw, "reason": err})
                if strict:
                    raise ValueError(f"Input contains duplicate event_id values; event IDs must be unique ({event.event_id}).")
                continue

            seen_ids.add(event.event_id)
            valid_events.append(event)
            report.valid_events += 1

    # Return events sorted in chronological order
    valid_events.sort(key=lambda e: (e.dt, e.event_id))
    return valid_events, report
