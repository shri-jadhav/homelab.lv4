"""Unit tests for the Wazuh SIEM alert adapter."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from detectlab.engine import DetectionEngine  # noqa: E402
from detectlab.wazuh_adapter import load_wazuh_alerts, map_wazuh_alert_to_event  # noqa: E402


class WazuhAdapterTests(unittest.TestCase):
    """Test importing and normalizing genuine Wazuh alerts.json structures."""

    def test_map_wazuh_logon_failure(self):
        wazuh_alert = {
            "timestamp": "2026-10-17T02:10:00.000+0000",
            "rule": {
                "level": 5,
                "description": "Logon Failure - Unknown user or bad password",
                "id": "60122",
                "mitre": {"id": ["T1110"], "tactic": ["Credential Access"]},
            },
            "agent": {"id": "001", "name": "WIN-LOQ", "ip": "127.0.0.1"},
            "data": {
                "win": {
                    "eventdata": {
                        "targetUserName": "a.patel",
                        "ipAddress": "198.51.100.22",
                        "subStatus": "0xc000006a",
                    },
                    "system": {"eventID": "4625", "computer": "WIN-LOQ"},
                }
            },
        }

        sec_event = map_wazuh_alert_to_event(wazuh_alert, event_index=1)
        self.assertEqual("auth", sec_event.event_type)
        self.assertEqual("failure", sec_event.outcome)
        self.assertEqual("a.patel", sec_event.user)
        self.assertEqual("198.51.100.22", sec_event.source_ip)
        self.assertEqual("WIN-LOQ", sec_event.host)
        self.assertEqual("4625", sec_event.extra["win_event_id"])
        # Original evidence preserved
        self.assertIn("raw_wazuh_alert", sec_event.extra)
        self.assertEqual("60122", sec_event.extra["raw_wazuh_alert"]["rule"]["id"])

    def test_map_wazuh_privileged_group_add(self):
        wazuh_alert = {
            "timestamp": "2026-10-17T02:15:00.000+0000",
            "rule": {
                "level": 10,
                "description": "User added to privileged local group",
                "id": "60114",
                "mitre": {"id": ["T1098"], "tactic": ["Persistence"]},
            },
            "agent": {"id": "001", "name": "WIN-LOQ", "ip": "127.0.0.1"},
            "data": {
                "win": {
                    "eventdata": {
                        "targetUserName": "Administrators",
                        "memberName": "CN=a.patel,CN=Users,DC=lab,DC=local",
                    },
                    "system": {"eventID": "4732", "computer": "WIN-LOQ"},
                }
            },
        }

        sec_event = map_wazuh_alert_to_event(wazuh_alert, event_index=2)
        self.assertEqual("privilege_change", sec_event.event_type)
        self.assertEqual("success", sec_event.outcome)
        self.assertEqual("Administrators", sec_event.role)

    def test_wazuh_alerts_feed_into_detection_engine(self):
        # 5 failure alerts + 1 success alert from Wazuh schema
        events = []
        for i in range(5):
            alert = {
                "timestamp": f"2026-10-17T02:0{i}:00.000+0000",
                "rule": {"level": 5, "description": "Logon Failure", "id": "60122"},
                "agent": {"name": "WIN-LOQ"},
                "data": {
                    "win": {
                        "eventdata": {"targetUserName": "john_doe", "ipAddress": "192.0.2.55"},
                        "system": {"eventID": "4625", "computer": "WIN-LOQ"},
                    }
                },
            }
            events.append(map_wazuh_alert_to_event(alert, i + 1))

        engine = DetectionEngine()
        alerts = engine.run(events)
        self.assertEqual(1, len(alerts))
        self.assertEqual("DET-AUTH-001", alerts[0].rule_id)
        self.assertEqual("user=john_doe; source_ip=192.0.2.55", alerts[0].entity)

    def test_missing_timestamp_raises_value_error(self):
        """Ensure missing timestamps fail validation rather than silently fabricating a date."""
        bad_alert = {
            "rule": {"id": "60122", "description": "Logon Failure"},
            "agent": {"name": "WIN-LOQ"},
            "data": {"win": {"eventdata": {"targetUserName": "bob"}}},
        }
        with self.assertRaisesRegex(ValueError, "missing a valid timestamp"):
            map_wazuh_alert_to_event(bad_alert, 1)

    def test_missing_source_ip_does_not_default_to_loopback(self):
        """Missing or '-' IP address in Windows logons must normalize to 'unknown', not '127.0.0.1'."""
        alert_no_ip = {
            "timestamp": "2026-10-17T02:00:00.000+0000",
            "rule": {"id": "60122", "description": "Logon Failure"},
            "data": {
                "win": {
                    "eventdata": {"targetUserName": "alice", "ipAddress": "-"},
                    "system": {"eventID": "4625"},
                }
            },
        }
        sec_event = map_wazuh_alert_to_event(alert_no_ip, 1)
        self.assertEqual("unknown", sec_event.source_ip)
        self.assertNotEqual("127.0.0.1", sec_event.source_ip)

    def test_non_auth_rules_are_not_classified_as_auth_by_broad_matching(self):
        """Rules with words 'success' or 'failed' (e.g. SCA checks, service protection) must not become auth events."""
        svc_alert = {
            "timestamp": "2026-10-17T02:00:00.000+0000",
            "rule": {"id": "60642", "description": "Software protection service scheduled successfully."},
            "data": {"win": {"system": {"eventID": "16384"}}},
        }
        event = map_wazuh_alert_to_event(svc_alert, 1)
        self.assertNotEqual("auth", event.event_type)
        self.assertEqual("system", event.event_type)

        sca_alert = {
            "timestamp": "2026-10-17T02:00:00.000+0000",
            "rule": {"id": "19007", "description": "CIS Benchmark check failed."},
            "data": {"sca": {"result": "failed"}},
        }
        event_sca = map_wazuh_alert_to_event(sca_alert, 2)
        self.assertNotEqual("auth", event_sca.event_type)
        self.assertEqual("system", event_sca.event_type)

    def test_load_wazuh_alerts_quarantines_malformed_records(self):
        """Malformed JSON lines in Wazuh alert exports must be tracked in IngestionReport."""
        import tempfile
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json", encoding="utf-8") as f:
            f.write('{"timestamp":"2026-10-17T02:00:00.000+0000","rule":{"id":"60122","description":"Logon Failure"},"data":{"win":{"eventdata":{"targetUserName":"u1"},"system":{"eventID":"4625"}}}}\n')
            f.write('invalid-json-content\n')
            f.write('{"rule":{"id":"60122"},"missing_timestamp":true}\n')
            temp_path = Path(f.name)

        try:
            events, report = load_wazuh_alerts(temp_path, strict=False)
            self.assertEqual(1, len(events))
            self.assertEqual(3, report.total_lines)
            self.assertEqual(1, report.valid_events)
            self.assertEqual(2, report.quarantined_events)
            self.assertEqual(2, len(report.errors))
        finally:
            temp_path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
