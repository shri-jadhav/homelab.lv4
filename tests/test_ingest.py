"""Unit tests for event ingestion, schema validation, and timestamp normalization."""
from __future__ import annotations

import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from detectlab.ingest import (  # noqa: E402
    load_events_from_jsonl,
    normalize_event_dict,
    parse_timestamp,
)


class EventIngestTests(unittest.TestCase):
    """Tests covering timestamp parsing, edge cases, schema normalization, and quarantine handling."""

    def test_parse_timestamp_formats(self):
        # UTC 'Z'
        dt1 = parse_timestamp("2026-10-16T09:00:00Z")
        self.assertEqual(timezone.utc, dt1.tzinfo)
        self.assertEqual(9, dt1.hour)

        # Explicit offset +05:30
        dt2 = parse_timestamp("2026-10-16T14:30:00+05:30")
        self.assertEqual(timezone.utc, dt2.tzinfo)
        self.assertEqual(9, dt2.hour)  # 14:30 +05:30 is 09:00:00 UTC

        # Negative offset -04:00
        dt3 = parse_timestamp("2026-10-16T05:00:00-04:00")
        self.assertEqual(timezone.utc, dt3.tzinfo)
        self.assertEqual(9, dt3.hour)  # 05:00 -04:00 is 09:00:00 UTC

        # Naive string (treated as UTC)
        dt4 = parse_timestamp("2026-10-16T09:00:00")
        self.assertEqual(timezone.utc, dt4.tzinfo)
        self.assertEqual(9, dt4.hour)

        # Epoch timestamp
        dt5 = parse_timestamp(1792141200)  # valid numeric epoch
        self.assertEqual(timezone.utc, dt5.tzinfo)

    def test_parse_invalid_timestamp_raises(self):
        with self.assertRaises(ValueError):
            parse_timestamp("not-a-timestamp")
        with self.assertRaises(ValueError):
            parse_timestamp("")

    def test_missing_required_fields_raises(self):
        base = {
            "event_id": "EV-01",
            "timestamp": "2026-10-16T09:00:00Z",
            "host": "DC-01",
            "event_type": "auth",
            "user": "alice",
        }
        for req in ["event_id", "timestamp", "host", "event_type", "user"]:
            bad = dict(base)
            del bad[req]
            with self.assertRaises(ValueError):
                normalize_event_dict(bad)

    def test_field_aliases_normalization(self):
        raw = {
            "id": "EV-ALIAS-01",
            "time": "2026-10-16T10:00:00Z",
            "computer_name": "WORKSTATION-01",
            "type": "auth",
            "username": "bob",
            "src_ip": "192.168.1.50",
            "result": "success",
        }
        event = normalize_event_dict(raw)
        self.assertEqual("EV-ALIAS-01", event.event_id)
        self.assertEqual("WORKSTATION-01", event.host)
        self.assertEqual("auth", event.event_type)
        self.assertEqual("bob", event.user)
        self.assertEqual("192.168.1.50", event.source_ip)
        self.assertEqual("success", event.outcome)

    def test_out_of_order_events_sorted_chronologically(self):
        p = ROOT / "data" / "events.jsonl"
        events, _ = load_events_from_jsonl(p)
        timestamps = [e.dt for e in events]
        self.assertEqual(sorted(timestamps), timestamps)

    def test_resilient_mode_quarantines_malformed_and_duplicate(self, tmp_path=None):
        import tempfile
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".jsonl", encoding="utf-8") as f:
            f.write('{"event_id":"OK-1","timestamp":"2026-10-16T09:00:00Z","host":"H1","event_type":"auth","user":"u1"}\n')
            f.write('not-json\n')
            f.write('{"event_id":"MISSING-USER","timestamp":"2026-10-16T09:01:00Z","host":"H1","event_type":"auth"}\n')
            f.write('{"event_id":"OK-1","timestamp":"2026-10-16T09:02:00Z","host":"H1","event_type":"auth","user":"u1"}\n')
            f.write('{"event_id":"OK-2","timestamp":"2026-10-16T09:03:00Z","host":"H1","event_type":"auth","user":"u2"}\n')
            temp_path = Path(f.name)

        try:
            # Resilient mode (strict=False)
            valid, report = load_events_from_jsonl(temp_path, strict=False)
            self.assertEqual(2, len(valid))
            self.assertEqual(["OK-1", "OK-2"], [e.event_id for e in valid])
            self.assertEqual(3, report.quarantined_events)
            self.assertEqual(1, report.duplicate_events)

            # Strict mode (strict=True) must fail on first error
            with self.assertRaises(ValueError):
                load_events_from_jsonl(temp_path, strict=True)
        finally:
            temp_path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
