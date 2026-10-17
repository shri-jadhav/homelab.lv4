"""I/O functions for loading JSONL events and writing structured artifacts."""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Iterable

from .correlation import group_incidents
from .ingest import load_events_from_jsonl, normalize_event_dict
from .models import Alert, Incident, IngestionReport, SecurityEvent
from .reporting import generate_html_report
from .rules import get_default_rule_catalog


def load_jsonl(path: Path | str) -> list[dict[str, Any]]:
    """Legacy-compatible loader returning raw event dictionaries.
    
    Uses resilient mode to read records, maintaining strict JSON parsing.
    """
    file_path = Path(path)
    events: list[dict[str, Any]] = []
    with file_path.open("r", encoding="utf-8-sig") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            try:
                event = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON in {file_path} at line {line_number}: {exc}") from exc
            if not isinstance(event, dict):
                raise ValueError(f"JSONL line {line_number} must contain one JSON object.")
            events.append(event)
    return events


def write_outputs(
    alerts: list[dict[str, Any]],
    event_count: int,
    out_dir: Path,
    incidents: list[dict[str, Any]] | None = None,
    events: list[SecurityEvent] | None = None,
    ingest_report: IngestionReport | None = None,
    data_source: str = "synthetic_jsonl",
) -> None:
    """Write structured detection artifacts (JSON, CSV, HTML, summary, incidents)."""
    out_dir.mkdir(parents=True, exist_ok=True)

    # 1. Write alerts.json
    (out_dir / "alerts.json").write_text(json.dumps(alerts, indent=2), encoding="utf-8")

    # 2. Correlate incidents if not explicitly provided
    if incidents is None:
        if events is not None:
            # Reconstruct Alert domain objects for correlation
            alert_objs = [
                Alert(
                    alert_id=a["alert_id"],
                    rule_id=a["rule_id"],
                    title=a["title"],
                    severity=a["severity"],
                    status=a.get("status", "new"),
                    entity=a["entity"],
                    first_seen=a["first_seen"],
                    last_seen=a["last_seen"],
                    event_count=a["event_count"],
                    event_ids=a["event_ids"],
                    mitre_attack=a["mitre_attack"],
                    mitre_tactics=a.get("mitre_tactics", []),
                    why_it_fired=a["why_it_fired"],
                    rule_threshold=a.get("rule_threshold", ""),
                    recommended_actions=a["recommended_actions"],
                    evidence=a.get("evidence", []),
                    context={
                        "user": a.get("user"),
                        "source_ip": a.get("source_ip"),
                        "role_granted": a.get("role_granted"),
                    },
                )
                for a in alerts
            ]
            incident_objs = group_incidents(alert_objs, events)
            incidents = [inc.to_dict() for inc in incident_objs]
        else:
            incidents = []

    # 3. Write incidents.json
    (out_dir / "incidents.json").write_text(json.dumps(incidents, indent=2), encoding="utf-8")

    # 4. Write alerts.csv
    fields = [
        "alert_id", "rule_id", "title", "severity", "status", "entity",
        "first_seen", "last_seen", "event_count", "mitre_attack",
        "mitre_tactics", "why_it_fired", "rule_threshold", "recommended_actions",
    ]
    with (out_dir / "alerts.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for alert in alerts:
            row = dict(alert)
            row["mitre_attack"] = ", ".join(row.get("mitre_attack", []))
            row["mitre_tactics"] = ", ".join(row.get("mitre_tactics", []))
            row["recommended_actions"] = " | ".join(row.get("recommended_actions", []))
            writer.writerow(row)

    # 5. Build summary metrics
    severities = {s: sum(1 for a in alerts if a["severity"] == s) for s in ["critical", "high", "medium", "low", "info"]}
    rules = sorted({a["rule_id"] for a in alerts})
    mitre_techs = sorted({tech for a in alerts for tech in a.get("mitre_attack", [])})

    note_str = (
        "Generated from genuine local Wazuh SIEM telemetry. Alerts require analyst validation."
        if data_source == "wazuh_siem"
        else "Generated from local synthetic lab dataset. Alerts require analyst validation."
    )
    summary: dict[str, Any] = {
        "data_source": data_source,
        "events_processed": event_count,
        "alerts_generated": len(alerts),
        "incidents_correlated": len(incidents),
        "severity_breakdown": severities,
        "rules_triggered": rules,
        "unique_rules_triggered": len(rules),
        "mitre_techniques_observed": mitre_techs,
        "note": note_str,
    }
    if ingest_report:
        summary["ingestion"] = ingest_report.to_dict()

    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    # 6. Rule coverage export
    catalog = get_default_rule_catalog()
    coverage_data = {
        "catalog_rules_count": len(catalog),
        "rules_triggered_count": len(rules),
        "rules": [r.to_dict() for r in catalog.values()],
    }
    (out_dir / "coverage.json").write_text(json.dumps(coverage_data, indent=2), encoding="utf-8")

    # 7. Write report.html
    html = generate_html_report(alerts, incidents, summary, catalog, ingest_report)
    (out_dir / "report.html").write_text(html, encoding="utf-8")
