"""Tests for the local rule-based analyzer."""

import unittest
from datetime import datetime, timedelta, timezone

from aws_tower.analyzer.local_analyzer import (
    AccessDeniedSpikeDetector,
    LocalAnalyzer,
    RootAccountUsageDetector,
)
from aws_tower.events.models import (
    Action,
    Actor,
    EventResult,
    EventSource,
    Resource,
    SecurityEvent,
    SourceNetwork,
)


def make_event(
    *,
    event_id: str = "evt-1",
    operation: str = "GetObject",
    actor_type: str = "IAMUser",
    actor_arn: str = "arn:aws:iam::123:user/alice",
    actor_username: str = "alice",
    source_ip: str = "10.0.0.1",
    region: str = "us-east-1",
    event_time: datetime | None = None,
    status: str = "SUCCESS",
    error_code: str | None = None,
    severity: str = "LOW",
) -> SecurityEvent:
    return SecurityEvent(
        event_id=event_id,
        event_time=event_time or datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc),
        source=EventSource(
            provider="aws",
            service="iam",
            collector="cloudtrail",
            event_type="AwsApiCall",
            event_name=operation,
        ),
        actor=Actor(
            type=actor_type,
            user_id="AIDAEXAMPLE",
            username=actor_username,
            arn=actor_arn,
        ),
        source_network=SourceNetwork(ip=source_ip, user_agent="aws-cli/2.0"),
        action=Action(category="read", operation=operation, read_only=True),
        resource=Resource(type="IAMUser", arn=actor_arn, region=region),
        result=EventResult(status=status, error_code=error_code),
        severity=severity,
    )


class TestLocalAnalyzer(unittest.TestCase):
    def test_empty_events_returns_zero_risk(self):
        analyzer = LocalAnalyzer(trusted_networks=["10.0.0.0/8"])
        result = analyzer.analyze_events([])
        self.assertEqual(result["risk_score"], 0.0)
        self.assertEqual(result["risk_level"], "LOW")
        self.assertEqual(result["analyzed_count"], 0)

    def test_restricted_activity_outside_hours_and_untrusted_ip(self):
        # Outside business hours (3am), untrusted IP, and a sensitive op.
        event = make_event(
            event_id="evt-priv",
            operation="AttachUserPolicy",
            source_ip="203.0.113.5",
            event_time=datetime(2026, 8, 30, 3, 0, tzinfo=timezone.utc),
            severity="HIGH",
        )
        analyzer = LocalAnalyzer(trusted_networks=["10.0.0.0/8"])
        result = analyzer.analyze_actor_behavior(
            "arn:aws:iam::123:user/alice", [event]
        )

        self.assertGreaterEqual(result["risk_score"], 6.0)
        detectors = {finding.detector for finding in result["findings"]}
        # The three rule types that should fire together.
        self.assertIn("restricted_activity", detectors)
        self.assertIn("out_of_company_ip", detectors)
        self.assertIn("irregular_hour", detectors)

    def test_root_account_usage_is_critical(self):
        event = make_event(
            event_id="evt-root",
            operation="PutBucketPolicy",
            actor_type="Root",
            actor_arn="arn:aws:iam::123:root",
            actor_username=None,
        )
        analyzer = LocalAnalyzer()
        result = analyzer.analyze_actor_behavior("arn:aws:iam::123:root", [event])

        detectors = {finding.detector for finding in result["findings"]}
        self.assertIn("root_account_usage", detectors)
        # Root usage should be CRITICAL severity.
        root_finding = next(
            f for f in result["findings"] if f.detector == "root_account_usage"
        )
        self.assertEqual(root_finding.severity, "CRITICAL")
        # And the overall risk should be high.
        self.assertIn(result["risk_level"], ("HIGH", "CRITICAL"))

    def test_trusted_ip_suppresses_out_of_company_ip(self):
        event = make_event(
            event_id="evt-trusted",
            operation="GetObject",
            source_ip="10.1.2.3",
        )
        analyzer = LocalAnalyzer(trusted_networks=["10.0.0.0/8"])
        result = analyzer.analyze_actor_behavior(
            "arn:aws:iam::123:user/alice", [event]
        )
        detectors = {finding.detector for finding in result["findings"]}
        self.assertNotIn("out_of_company_ip", detectors)

    def test_service_hostname_suppresses_out_of_company_ip(self):
        event = make_event(
            event_id="evt-service",
            source_ip="resource-explorer-2.amazonaws.com",
        )
        analyzer = LocalAnalyzer(trusted_networks=["10.0.0.0/8"])

        result = analyzer.analyze_actor_behavior(
            "arn:aws:iam::123:user/alice", [event]
        )

        detectors = {finding.detector for finding in result["findings"]}
        self.assertNotIn("out_of_company_ip", detectors)

    def test_access_denied_spike_fires_after_threshold(self):
        analyzer = LocalAnalyzer(
            trusted_networks=["10.0.0.0/8"],
            access_denied_window_minutes=10,
            access_denied_threshold=3,
        )
        events = [
            make_event(
                event_id=f"evt-{i}",
                operation="GetObject",
                source_ip="10.0.0.5",
                event_time=datetime(
                    2026, 8, 30, 12, i, tzinfo=timezone.utc
                ),
                status="DENIED",
                error_code="AccessDenied",
            )
            for i in range(3)
        ]
        results = [
            analyzer.analyze_actor_behavior(
                "arn:aws:iam::123:user/alice", [event]
            )
            for event in events
        ]
        # The third event should have produced an access-denied-spike finding.
        last_detectors = {
            finding.detector for finding in results[-1]["findings"]
        }
        self.assertIn("access_denied_spike", last_detectors)


class TestRootAccountUsageDetector(unittest.TestCase):
    def test_only_fires_for_root(self):
        detector = RootAccountUsageDetector()
        non_root = make_event(actor_type="IAMUser")
        root = make_event(actor_type="Root", actor_arn="arn:aws:iam::1:root", actor_username=None)
        self.assertIsNone(detector.detect(non_root))
        self.assertIsNotNone(detector.detect(root))


class TestCrossActorIndependence(unittest.TestCase):
    """UEBA baselines should not leak across actors.

    Two actors, each with a single 'first-time sensitive action' event.
    Analyzing them in either order should produce the same per-actor
    risk — the earlier implementation had actor B's analysis see actor
    A's events in B's 'recent history'.
    """

    def _event(self, event_id, actor_arn, time):
        return make_event(
            event_id=event_id,
            operation="AttachUserPolicy",
            actor_arn=actor_arn,
            actor_username=actor_arn.split("/")[-1],
            source_ip="10.0.0.5",
            event_time=time,
            severity="HIGH",
        )

    def test_ueba_results_order_independent(self):
        t = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)
        alice_evt = self._event("evt-a", "arn:aws:iam::1:user/alice", t)
        bob_evt = self._event("evt-b", "arn:aws:iam::1:user/bob", t + timedelta(seconds=10))

        # Order 1: Alice then Bob.
        a1 = LocalAnalyzer(trusted_networks=["10.0.0.0/8"])
        a1.analyze_events([alice_evt, bob_evt])
        alice_score_order1 = a1.analyze_actor_behavior("arn:aws:iam::1:user/alice", [alice_evt, bob_evt])["risk_score"]
        bob_score_order1 = a1.analyze_actor_behavior("arn:aws:iam::1:user/bob", [alice_evt, bob_evt])["risk_score"]

        # Order 2: Bob then Alice, fresh analyzer.
        a2 = LocalAnalyzer(trusted_networks=["10.0.0.0/8"])
        a2.analyze_events([bob_evt, alice_evt])
        alice_score_order2 = a2.analyze_actor_behavior("arn:aws:iam::1:user/alice", [bob_evt, alice_evt])["risk_score"]
        bob_score_order2 = a2.analyze_actor_behavior("arn:aws:iam::1:user/bob", [bob_evt, alice_evt])["risk_score"]

        self.assertEqual(alice_score_order1, alice_score_order2)
        self.assertEqual(bob_score_order1, bob_score_order2)

    def test_impossible_travel_uses_only_actor_events(self):
        """Actor B's analysis must not see Actor A's events in the recent window."""
        t = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)
        # Alice in eu-west-1, Bob in us-east-1, both at the same time.
        alice_evt = make_event(
            event_id="evt-a",
            operation="GetObject",
            actor_arn="arn:aws:iam::1:user/alice",
            source_ip="10.0.0.5",
            region="eu-west-1",
            event_time=t,
        )
        bob_evt = make_event(
            event_id="evt-b",
            operation="GetObject",
            actor_arn="arn:aws:iam::1:user/bob",
            source_ip="10.0.0.6",
            region="us-east-1",
            event_time=t,
        )
        analyzer = LocalAnalyzer(trusted_networks=["10.0.0.0/8"])
        analyzer.analyze_events([alice_evt, bob_evt])
        bob_finding = analyzer.analyze_actor_behavior(
            "arn:aws:iam::1:user/bob", [alice_evt, bob_evt]
        )
        # Bob's analysis sees only Bob's single event; no "recent" history
        # from Alice, so no impossible-travel finding should fire.
        detectors = {f.detector for f in bob_finding["findings"]}
        self.assertNotIn("ueba_impossible_travel", detectors)


class TestAccessDeniedSpikeDetector(unittest.TestCase):
    def test_requires_threshold_to_be_reached(self):
        detector = AccessDeniedSpikeDetector(window_minutes=10, threshold=3)
        # Two events: not enough.
        for i in range(2):
            event = make_event(
                event_id=f"evt-{i}",
                source_ip="10.0.0.1",
                event_time=datetime(2026, 8, 30, 12, i, tzinfo=timezone.utc),
                status="DENIED",
                error_code="AccessDenied",
            )
            self.assertIsNone(detector.detect(event))

        # Third event crosses the threshold.
        third = make_event(
            event_id="evt-2",
            source_ip="10.0.0.1",
            event_time=datetime(2026, 8, 30, 12, 2, tzinfo=timezone.utc),
            status="DENIED",
            error_code="AccessDenied",
        )
        self.assertIsNotNone(detector.detect(third))


if __name__ == "__main__":
    unittest.main()
