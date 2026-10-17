"""Comprehensive unit tests for the detection engine and individual rule logic."""
from __future__ import annotations

import json
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from detectlab.correlation import group_incidents  # noqa: E402
from detectlab.engine import detect, validate_events  # noqa: E402
from detectlab.io import load_jsonl  # noqa: E402
from detectlab.models import Alert, SecurityEvent  # noqa: E402
from detectlab.rules import DetectionConfig  # noqa: E402


class DetectionEngineTests(unittest.TestCase):
    """Core regression and baseline tests preserved from starter lab."""

    @classmethod
    def setUpClass(cls):
        cls.events = load_jsonl(ROOT / "data" / "events.jsonl")
        cls.alerts = detect(cls.events)

    def test_all_four_rule_families_trigger_on_demo_data(self):
        self.assertEqual(
            {"DET-AUTH-001", "DET-AUTH-002", "DET-AUTH-003", "DET-IAM-001"},
            {a["rule_id"] for a in self.alerts},
        )

    def test_single_failed_login_is_not_enough_to_alert(self):
        alerts = detect([e for e in self.events if e["event_id"] in {"E008", "E009"}])
        self.assertEqual([], alerts)

    def test_privilege_alert_contains_role_and_recommended_actions(self):
        alert = next(a for a in self.alerts if a["rule_id"] == "DET-IAM-001")
        self.assertEqual("GlobalAdmin", alert["role_granted"])
        self.assertIn("approved change ticket", " ".join(alert["recommended_actions"]))
        self.assertIn("E007", alert["event_ids"])

    def test_alert_has_explanation_and_attack_mapping(self):
        for alert in self.alerts:
            self.assertTrue(alert["why_it_fired"])
            self.assertTrue(alert["mitre_attack"])
            self.assertTrue(alert["recommended_actions"])

    def test_duplicate_event_ids_fail_validation(self):
        duplicated = [dict(self.events[0]), dict(self.events[0])]
        with self.assertRaisesRegex(ValueError, "duplicate event_id"):
            validate_events(duplicated)

    def test_unknown_event_type_fails_validation(self):
        bad = dict(self.events[0])
        bad["event_type"] = "something_else"
        with self.assertRaisesRegex(ValueError, "unsupported event_type"):
            validate_events([bad])

    def test_json_output_can_be_serialized(self):
        json.dumps(self.alerts)


class AdvancedDetectionBoundaryTests(unittest.TestCase):
    """Boundary conditions, window thresholds, entity isolation, and regression tests."""

    def _create_auth_event(self, eid: str, dt_str: str, user: str, ip: str, outcome: str = "failure") -> dict:
        return {
            "event_id": eid,
            "timestamp": dt_str,
            "host": "IDP-01",
            "event_type": "auth",
            "user": user,
            "source_ip": ip,
            "outcome": outcome,
            "message": "Synthetic test event",
        }

    def test_separate_auth_bursts_for_same_user_are_not_merged(self):
        """Separate brute-force bursts 19 minutes apart form separate incidents."""
        events = [
            SecurityEvent(
                event_id=f"EV-BURST-{i}",
                timestamp_str=timestamp,
                dt=datetime.fromisoformat(timestamp.replace("Z", "+00:00")),
                host="WIN-HOST",
                event_type="auth",
                user="sam",
                source_ip="127.0.0.1",
                outcome="failure",
            )
            for i, timestamp in enumerate([
                "2026-10-16T10:00:00Z",
                "2026-10-16T10:01:00Z",
                "2026-10-16T10:02:00Z",
                "2026-10-16T10:03:00Z",
                "2026-10-16T10:04:00Z",
                "2026-10-16T10:23:00Z",
                "2026-10-16T10:23:30Z",
                "2026-10-16T10:24:00Z",
                "2026-10-16T10:24:30Z",
                "2026-10-16T10:25:00Z",
            ])
        ]

        def make_alert(alert_id, first_seen, last_seen, event_ids):
            return Alert(
                alert_id=alert_id,
                rule_id="DET-AUTH-001",
                title="Repeated authentication failures",
                severity="medium",
                status="new",
                entity="user=sam; source_ip=127.0.0.1",
                first_seen=first_seen,
                last_seen=last_seen,
                event_count=len(event_ids),
                event_ids=event_ids,
                mitre_attack=["T1110"],
                why_it_fired="Repeated authentication failures",
                rule_threshold="5 failures / 5 minutes",
                recommended_actions=["Investigate authentication failures"],
                context={"user": "sam", "source_ip": "127.0.0.1"},
            )

        alert1 = make_alert(
            "BURST-1",
            "2026-10-16T10:00:00Z",
            "2026-10-16T10:04:00Z",
            [f"EV-BURST-{i}" for i in range(5)],
        )
        alert2 = make_alert(
            "BURST-2",
            "2026-10-16T10:23:00Z",
            "2026-10-16T10:25:00Z",
            [f"EV-BURST-{i}" for i in range(5, 10)],
        )

        incidents = group_incidents([alert1, alert2], events, correlation_window_hours=4.0)

        self.assertEqual(
            2,
            len(incidents),
            "Separate authentication bursts should not be merged into one incident",
        )

    def test_brute_force_threshold_boundaries(self):
        """Test exactly 4 failures (no alert) vs 5 failures (alerts)."""
        # 4 failures in 2 minutes (threshold is 5) -> No alert
        under_thresh = [
            self._create_auth_event(f"E-BF4-{i}", f"2026-10-16T10:0{i}:00Z", "target_user", "192.0.2.1")
            for i in range(4)
        ]
        self.assertEqual([], detect(under_thresh))

        # 5 failures in 2 minutes -> Alerts DET-AUTH-001
        at_thresh = under_thresh + [
            self._create_auth_event("E-BF5-5", "2026-10-16T10:04:00Z", "target_user", "192.0.2.1")
        ]
        alerts = detect(at_thresh)
        self.assertEqual(1, len(alerts))
        self.assertEqual("DET-AUTH-001", alerts[0]["rule_id"])

    def test_brute_force_time_window_boundary(self):
        """Test 5 failures inside 5 minutes vs 5 failures spread over 6 minutes."""
        # Spread over 6 minutes (0m, 1.5m, 3m, 4.5m, 6m) -> No 5-minute window has 5 failures
        spread_events = [
            self._create_auth_event("E-SP-1", "2026-10-16T10:00:00Z", "target_user", "192.0.2.1"),
            self._create_auth_event("E-SP-2", "2026-10-16T10:01:30Z", "target_user", "192.0.2.1"),
            self._create_auth_event("E-SP-3", "2026-10-16T10:03:00Z", "target_user", "192.0.2.1"),
            self._create_auth_event("E-SP-4", "2026-10-16T10:04:30Z", "target_user", "192.0.2.1"),
            self._create_auth_event("E-SP-5", "2026-10-16T10:06:00Z", "target_user", "192.0.2.1"),
        ]
        self.assertEqual([], detect(spread_events))

    def test_source_ip_and_user_isolation(self):
        """Ensure failure counts are isolated per (source_ip, user) pair."""
        # 3 failures from IP1 for user1, 3 failures from IP2 for user1 (neither meets 5)
        mixed_events = [
            self._create_auth_event("E-MIX-1", "2026-10-16T10:00:00Z", "user1", "192.0.2.1"),
            self._create_auth_event("E-MIX-2", "2026-10-16T10:00:30Z", "user1", "192.0.2.1"),
            self._create_auth_event("E-MIX-3", "2026-10-16T10:01:00Z", "user1", "192.0.2.1"),
            self._create_auth_event("E-MIX-4", "2026-10-16T10:01:30Z", "user1", "192.0.2.2"),
            self._create_auth_event("E-MIX-5", "2026-10-16T10:02:00Z", "user1", "192.0.2.2"),
            self._create_auth_event("E-MIX-6", "2026-10-16T10:02:30Z", "user1", "192.0.2.2"),
        ]
        alerts = detect(mixed_events)
        # Should NOT trigger DET-AUTH-001 because neither IP had 5 failures alone
        self.assertNotIn("DET-AUTH-001", {a["rule_id"] for a in alerts})

    def test_spray_threshold_boundary(self):
        """Test 7 distinct users (no alert) vs 8 distinct users (alerts DET-AUTH-002)."""
        # 7 distinct users
        events_7 = [
            self._create_auth_event(f"E-SP7-{i}", f"2026-10-16T10:0{i}:00Z", f"user_{i}", "198.51.100.5")
            for i in range(7)
        ]
        self.assertEqual([], detect(events_7))

        # 8 distinct users
        events_8 = events_7 + [
            self._create_auth_event("E-SP8-7", "2026-10-16T10:07:00Z", "user_7", "198.51.100.5")
        ]
        alerts = detect(events_8)
        self.assertIn("DET-AUTH-002", {a["rule_id"] for a in alerts})

    def test_regression_multiple_brute_force_bursts_detected(self):
        """Regression test: multiple separate attack bursts across time for the same user/IP must both alert."""
        # Burst 1 at 09:00 (5 failures)
        burst_1 = [
            self._create_auth_event(f"E-B1-{i}", f"2026-10-16T09:0{i}:00Z", "victim", "192.0.2.88")
            for i in range(5)
        ]
        # Burst 2 at 14:00 (5 failures)
        burst_2 = [
            self._create_auth_event(f"E-B2-{i}", f"2026-10-16T14:0{i}:00Z", "victim", "192.0.2.88")
            for i in range(5)
        ]
        alerts = detect(burst_1 + burst_2)
        bf_alerts = [a for a in alerts if a["rule_id"] == "DET-AUTH-001"]
        self.assertEqual(2, len(bf_alerts))
        # Verify both bursts are accounted for in events
        all_eids = [eid for a in bf_alerts for eid in a["event_ids"]]
        self.assertIn("E-B1-0", all_eids)
        self.assertIn("E-B2-0", all_eids)

    def test_approved_privilege_change_is_not_alerted(self):
        """Test that privilege changes with approved change ticket do NOT trigger DET-IAM-001."""
        events = [
            self._create_auth_event(f"E-AP-{i}", f"2026-10-16T09:0{i}:00Z", "bob", "192.0.2.10")
            for i in range(5)
        ]
        events.append(self._create_auth_event("E-AP-SUCC", "2026-10-16T09:06:00Z", "bob", "192.0.2.10", "success"))
        # Approved role change
        events.append({
            "event_id": "E-AP-ROLE",
            "timestamp": "2026-10-16T09:10:00Z",
            "host": "IDP-01",
            "event_type": "privilege_change",
            "user": "bob",
            "source_ip": "192.0.2.10",
            "role": "GlobalAdmin",
            "ticket_id": "CHG-4040",
            "approved": True,
            "message": "Authorized maintenance grant",
        })
        alerts = detect(events)
        # DET-AUTH-001 and DET-AUTH-003 fire, but DET-IAM-001 MUST NOT fire due to approved change ticket
        self.assertNotIn("DET-IAM-001", {a["rule_id"] for a in alerts})

    def test_privilege_change_outside_window_does_not_alert(self):
        """Test that privilege change 30 minutes after suspicious login does not alert."""
        events = [
            self._create_auth_event(f"E-EX-{i}", f"2026-10-16T09:0{i}:00Z", "sam", "192.0.2.10")
            for i in range(5)
        ]
        events.append(self._create_auth_event("E-EX-SUCC", "2026-10-16T09:06:00Z", "sam", "192.0.2.10", "success"))
        # Role change at 09:40:00 (34 minutes later; window is 15 minutes)
        events.append({
            "event_id": "E-EX-ROLE",
            "timestamp": "2026-10-16T09:40:00Z",
            "host": "IDP-01",
            "event_type": "privilege_change",
            "user": "sam",
            "source_ip": "192.0.2.10",
            "role": "GlobalAdmin",
            "message": "Delayed role change",
        })
        alerts = detect(events)
        self.assertNotIn("DET-IAM-001", {a["rule_id"] for a in alerts})

    def test_mfa_denial_detection(self):
        """Test DET-AUTH-004 triggers on 2 MFA denials within 10 minutes."""
        events = [
            {
                "event_id": "E-MFA-1",
                "timestamp": "2026-10-16T11:00:00Z",
                "host": "IDP-01",
                "event_type": "mfa_denial",
                "user": "exec_user",
                "source_ip": "203.0.113.1",
                "outcome": "mfa_denied",
                "message": "Push rejected",
            },
            {
                "event_id": "E-MFA-2",
                "timestamp": "2026-10-16T11:02:00Z",
                "host": "IDP-01",
                "event_type": "mfa_denial",
                "user": "exec_user",
                "source_ip": "203.0.113.1",
                "outcome": "mfa_denied",
                "message": "Push rejected",
            },
        ]
        alerts = detect(events)
        self.assertIn("DET-AUTH-004", {a["rule_id"] for a in alerts})

    def test_distributed_credential_attack_detection(self):
        """Test DET-NET-001 triggers on 4 distinct source IPs against 1 user."""
        events = [
            self._create_auth_event(f"E-DIST-{i}", f"2026-10-16T12:0{i}:00Z", "target_vip", f"198.51.100.{10+i}")
            for i in range(4)
        ]
        alerts = detect(events)
        self.assertIn("DET-NET-001", {a["rule_id"] for a in alerts})

    def test_unrelated_users_sharing_source_ip_are_not_merged_into_single_incident(self):
        """Unrelated brute-force attacks against different users from the same IP (e.g. 127.0.0.1) must not merge."""
        events_alice = [
            SecurityEvent(
                event_id=f"EV-ALICE-{i}",
                timestamp_str=f"2026-10-16T10:0{i}:00Z",
                dt=datetime(2026, 10, 16, 10, i, tzinfo=timezone.utc),
                host="WIN-HOST",
                event_type="auth",
                user="alice",
                source_ip="127.0.0.1",
                outcome="failure",
            )
            for i in range(5)
        ]
        events_bob = [
            SecurityEvent(
                event_id=f"EV-BOB-{i}",
                timestamp_str=f"2026-10-16T10:0{i}:30Z",
                dt=datetime(2026, 10, 16, 10, i, 30, tzinfo=timezone.utc),
                host="WIN-HOST",
                event_type="auth",
                user="bob",
                source_ip="127.0.0.1",
                outcome="failure",
            )
            for i in range(5)
        ]
        all_events = events_alice + events_bob

        alert_alice = Alert(
            alert_id="ALERT-ALICE",
            rule_id="DET-AUTH-001",
            title="Repeated authentication failures",
            severity="medium",
            status="new",
            entity="user=alice; source_ip=127.0.0.1",
            first_seen="2026-10-16T10:00:00Z",
            last_seen="2026-10-16T10:04:00Z",
            event_count=5,
            event_ids=[e.event_id for e in events_alice],
            mitre_attack=["T1110"],
            why_it_fired="Brute force against alice",
            rule_threshold="5 failures / 5 minutes",
            recommended_actions=["Verify alice"],
            context={"user": "alice", "source_ip": "127.0.0.1"},
        )
        alert_bob = Alert(
            alert_id="ALERT-BOB",
            rule_id="DET-AUTH-001",
            title="Repeated authentication failures",
            severity="medium",
            status="new",
            entity="user=bob; source_ip=127.0.0.1",
            first_seen="2026-10-16T10:00:30Z",
            last_seen="2026-10-16T10:04:30Z",
            event_count=5,
            event_ids=[e.event_id for e in events_bob],
            mitre_attack=["T1110"],
            why_it_fired="Brute force against bob",
            rule_threshold="5 failures / 5 minutes",
            recommended_actions=["Verify bob"],
            context={"user": "bob", "source_ip": "127.0.0.1"},
        )

        incidents = group_incidents([alert_alice, alert_bob], all_events)
        # Must produce TWO distinct incidents, not merged together!
        self.assertEqual(2, len(incidents))
        entities = {inc.entity for inc in incidents}
        self.assertTrue(any("alice" in ent for ent in entities))
        self.assertTrue(any("bob" in ent for ent in entities))

    def test_alerts_outside_correlation_time_window_are_not_merged(self):
        """Alerts occurring 24 hours apart must form separate incidents."""
        events_d1 = [
            SecurityEvent(
                event_id="EV-D1-1",
                timestamp_str="2026-10-16T10:00:00Z",
                dt=datetime(2026, 10, 16, 10, 0, tzinfo=timezone.utc),
                host="H1",
                event_type="auth",
                user="sam",
                source_ip="192.0.2.1",
                outcome="failure",
            )
        ]
        events_d2 = [
            SecurityEvent(
                event_id="EV-D2-1",
                timestamp_str="2026-10-17T10:00:00Z",
                dt=datetime(2026, 10, 17, 10, 0, tzinfo=timezone.utc),
                host="H1",
                event_type="auth",
                user="sam",
                source_ip="192.0.2.1",
                outcome="failure",
            )
        ]
        a1 = Alert(
            alert_id="A-D1",
            rule_id="DET-AUTH-001",
            title="Burst 1",
            severity="medium",
            status="new",
            entity="user=sam",
            first_seen="2026-10-16T10:00:00Z",
            last_seen="2026-10-16T10:05:00Z",
            event_count=1,
            event_ids=["EV-D1-1"],
            mitre_attack=["T1110"],
            why_it_fired="Burst 1",
            rule_threshold="5/5m",
            recommended_actions=[],
            context={"user": "sam", "source_ip": "192.0.2.1"},
        )
        a2 = Alert(
            alert_id="A-D2",
            rule_id="DET-AUTH-001",
            title="Burst 2",
            severity="medium",
            status="new",
            entity="user=sam",
            first_seen="2026-10-17T10:00:00Z",
            last_seen="2026-10-17T10:05:00Z",
            event_count=1,
            event_ids=["EV-D2-1"],
            mitre_attack=["T1110"],
            why_it_fired="Burst 2",
            rule_threshold="5/5m",
            recommended_actions=[],
            context={"user": "sam", "source_ip": "192.0.2.1"},
        )
        incidents = group_incidents([a1, a2], events_d1 + events_d2, correlation_window_hours=4.0)
        self.assertEqual(2, len(incidents))

    def test_incident_alert_count_and_event_count_semantics(self):
        """Verify Incident reports both alert_count (rule triggers) and event_count (raw events) explicitly."""
        events = [
            SecurityEvent(
                event_id=f"EV-SEM-{i}",
                timestamp_str=f"2026-10-16T10:0{i}:00Z",
                dt=datetime(2026, 10, 16, 10, i, tzinfo=timezone.utc),
                host="H1",
                event_type="auth",
                user="target",
                source_ip="192.0.2.1",
                outcome="failure",
            )
            for i in range(5)
        ]
        alert = Alert(
            alert_id="ALERT-SEM",
            rule_id="DET-AUTH-001",
            title="Repeated authentication failures",
            severity="medium",
            status="new",
            entity="user=target",
            first_seen="2026-10-16T10:00:00Z",
            last_seen="2026-10-16T10:04:00Z",
            event_count=5,
            event_ids=[e.event_id for e in events],
            mitre_attack=["T1110"],
            why_it_fired="Fired on 5 failures",
            rule_threshold="5/5m",
            recommended_actions=[],
            context={"user": "target", "source_ip": "192.0.2.1"},
        )
        incidents = group_incidents([alert], events)
        self.assertEqual(1, len(incidents))
        inc_dict = incidents[0].to_dict()
        self.assertEqual(1, inc_dict["alert_count"])
        self.assertEqual(5, inc_dict["event_count"])
        self.assertEqual(5, len(inc_dict["timeline"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
