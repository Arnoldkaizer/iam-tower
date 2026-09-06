"""Tests for the shared risk helpers."""

import unittest
from datetime import datetime, timezone

from aws_tower.detection.correlation import RiskCorrelator
from aws_tower.detection.models import DetectionFinding
from aws_tower.events.models import (
    Action,
    Actor,
    EventResult,
    EventSource,
    Resource,
    SecurityEvent,
    SourceNetwork,
)
from aws_tower.risk import actor_matches, score_to_risk_level


def _finding(severity: str, detector: str = "test") -> DetectionFinding:
    return DetectionFinding(
        detector=detector,
        title="Test finding",
        description="Test finding",
        severity=severity,
        event_id="evt-1",
    )


class TestRiskCorrelator(unittest.TestCase):
    def test_score_stays_within_zero_to_ten_with_many_findings(self):
        result = RiskCorrelator().correlate([_finding("CRITICAL") for _ in range(20)])
        self.assertEqual(result.score, 10.0)

    def test_correlation_boost_stays_within_zero_to_ten(self):
        findings = [
            _finding("HIGH", "restricted_activity"),
            _finding("HIGH", "out_of_company_ip"),
            _finding("MEDIUM", "irregular_hour"),
        ]
        result = RiskCorrelator().correlate(findings)
        self.assertGreaterEqual(result.score, 0.0)
        self.assertLessEqual(result.score, 10.0)


class TestScoreToRiskLevel(unittest.TestCase):
    def test_thresholds(self):
        self.assertEqual(score_to_risk_level(0.0), "LOW")
        self.assertEqual(score_to_risk_level(2.9), "LOW")
        self.assertEqual(score_to_risk_level(3.0), "MEDIUM")
        self.assertEqual(score_to_risk_level(5.9), "MEDIUM")
        self.assertEqual(score_to_risk_level(6.0), "HIGH")
        self.assertEqual(score_to_risk_level(7.9), "HIGH")
        self.assertEqual(score_to_risk_level(8.0), "CRITICAL")
        self.assertEqual(score_to_risk_level(10.0), "CRITICAL")


def _make_event(actor: Actor) -> SecurityEvent:
    return SecurityEvent(
        event_id="evt-1",
        event_time=datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc),
        source=EventSource(
            provider="aws",
            service="iam",
            collector="cloudtrail",
            event_type="AwsApiCall",
            event_name="GetObject",
        ),
        actor=actor,
        source_network=SourceNetwork(ip="10.0.0.1"),
        action=Action(category="read", operation="GetObject", read_only=True),
        resource=Resource(type="IAMUser", arn="arn:aws:iam::1:user/alice"),
        result=EventResult(status="SUCCESS"),
        severity="LOW",
    )


class TestActorMatches(unittest.TestCase):
    def test_matches_by_username(self):
        event = _make_event(Actor(type="IAMUser", username="alice", arn="arn:aws:iam::1:user/alice"))
        self.assertTrue(actor_matches(event, "alice"))

    def test_matches_by_user_id(self):
        event = _make_event(Actor(type="IAMUser", user_id="AIDAEXAMPLE"))
        self.assertTrue(actor_matches(event, "AIDAEXAMPLE"))

    def test_matches_by_full_arn(self):
        event = _make_event(Actor(type="IAMUser", arn="arn:aws:iam::1:user/alice"))
        self.assertTrue(actor_matches(event, "arn:aws:iam::1:user/alice"))

    def test_matches_by_arn_substring(self):
        event = _make_event(Actor(type="IAMUser", arn="arn:aws:iam::1:user/alice"))
        # Partial ARN match (used by the previous analyzer implementation).
        self.assertTrue(actor_matches(event, "user/alice"))

    def test_no_match_for_different_actor(self):
        event = _make_event(Actor(type="IAMUser", username="alice", arn="arn:aws:iam::1:user/alice"))
        self.assertFalse(actor_matches(event, "bob"))

    def test_no_match_for_empty_query(self):
        event = _make_event(Actor(type="IAMUser", username="alice"))
        self.assertFalse(actor_matches(event, ""))

    def test_no_match_when_actor_field_missing(self):
        # Empty actor with a non-empty query shouldn't crash.
        event = _make_event(Actor(type="IAMUser"))
        self.assertFalse(actor_matches(event, "alice"))


if __name__ == "__main__":
    unittest.main()
