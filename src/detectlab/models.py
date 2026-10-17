"""Domain models for events, alerts, incidents, and detection rules."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


SEVERITY_ORDER = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


def severity_rank(sev: str) -> int:
    """Return numeric rank for sorting severities (higher is more severe)."""
    return SEVERITY_ORDER.get(str(sev).lower(), 0)


@dataclass
class SecurityEvent:
    """Normalized security log event."""
    event_id: str
    timestamp_str: str
    dt: datetime
    host: str
    event_type: str
    user: str
    source_ip: str = "unknown"
    outcome: str = "unknown"
    role: str = ""
    message: str = ""
    ticket_id: str = ""
    approved: bool = False
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert normalized event to dictionary."""
        data = {
            "event_id": self.event_id,
            "timestamp": self.timestamp_str,
            "host": self.host,
            "event_type": self.event_type,
            "user": self.user,
            "source_ip": self.source_ip,
            "outcome": self.outcome,
            "role": self.role,
            "message": self.message,
        }
        if self.ticket_id:
            data["ticket_id"] = self.ticket_id
        if self.approved:
            data["approved"] = self.approved
        if self.extra:
            data["extra"] = self.extra
        return data


@dataclass
class Alert:
    """Explainable SOC detection alert."""
    alert_id: str
    rule_id: str
    title: str
    severity: str
    status: str
    entity: str
    first_seen: str
    last_seen: str
    event_count: int
    event_ids: list[str]
    mitre_attack: list[str]
    why_it_fired: str
    rule_threshold: str
    recommended_actions: list[str]
    mitre_tactics: list[str] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert alert to dictionary matching legacy schema with enhancements."""
        res: dict[str, Any] = {
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.lower(),
            "status": self.status,
            "entity": self.entity,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "event_count": self.event_count,
            "event_ids": list(self.event_ids),
            "mitre_attack": list(self.mitre_attack),
            "mitre_tactics": list(self.mitre_tactics),
            "why_it_fired": self.why_it_fired,
            "rule_threshold": self.rule_threshold,
            "recommended_actions": list(self.recommended_actions),
        }
        if self.evidence:
            res["evidence"] = self.evidence
        # Merge context keys for backwards compatibility with tests and callers
        if self.context:
            res.update(self.context)
        return res


@dataclass
class Incident:
    """Correlated cluster of alerts representing a security incident."""
    incident_id: str
    title: str
    severity: str
    status: str
    entity: str
    first_seen: str
    last_seen: str
    alerts: list[Alert]
    mitre_attack: list[str]
    mitre_tactics: list[str]
    timeline: list[dict[str, Any]]
    summary: str
    recommended_actions: list[str]

    def to_dict(self) -> dict[str, Any]:
        """Convert incident to dictionary."""
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "severity": self.severity.lower(),
            "status": self.status,
            "entity": self.entity,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "alert_count": len(self.alerts),
            "event_count": len(self.timeline),
            "alert_ids": [a.alert_id for a in self.alerts],
            "rule_ids": sorted({a.rule_id for a in self.alerts}),
            "mitre_attack": self.mitre_attack,
            "mitre_tactics": self.mitre_tactics,
            "timeline": self.timeline,
            "summary": self.summary,
            "recommended_actions": self.recommended_actions,
        }


@dataclass
class IngestionReport:
    """Metrics and diagnostics from telemetry ingestion."""
    total_lines: int = 0
    valid_events: int = 0
    quarantined_events: int = 0
    duplicate_events: int = 0
    dropped_empty_or_comments: int = 0
    errors: list[str] = field(default_factory=list)
    quarantined_records: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_lines": self.total_lines,
            "valid_events": self.valid_events,
            "quarantined_events": self.quarantined_events,
            "duplicate_events": self.duplicate_events,
            "dropped_empty_or_comments": self.dropped_empty_or_comments,
            "error_count": len(self.errors),
            "errors": self.errors[:20],  # cap in summary
        }
