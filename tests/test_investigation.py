"""Tests for the investigation engine."""

import unittest
from datetime import datetime, timezone

from aws_tower.assessment.in_memory import InMemoryAssessmentRepository
from aws_tower.events.in_memory import InMemoryEventRepository
from aws_tower.events.models import (
    Action,
    Actor,
    EventResult,
    EventSource,
    Resource,
    SecurityEvent,
    SourceNetwork,
)
from aws_tower.tower.investigation import InvestigationEngine


def _make_event(
    *,
    event_id: str,
    operation: str,
    actor_arn: str,
    source_ip: str,
    region: str = "us-east-1",
    event_time: datetime | None = None,
    status: str = "SUCCESS",
) -> SecurityEvent:
    return SecurityEvent(
        event_id=event_id,
        event_time=event_time or datetime(2026, 8, 30, 3, 0, tzinfo=timezone.utc),
        source=EventSource(
            provider="aws",
            service="iam",
            collector="cloudtrail",
            event_type="AwsApiCall",
            event_name=operation,
        ),
        actor=Actor(
            type="IAMUser",
            user_id="AIDAEXAMPLE",
            username=actor_arn.split("/")[-1],
            arn=actor_arn,
        ),
        source_network=SourceNetwork(ip=source_ip, user_agent="aws-cli/2.0"),
        action=Action(category="configuration", operation=operation, read_only=False),
        resource=Resource(type="IAMUser", arn=actor_arn, region=region),
        result=EventResult(status=status),
        severity="HIGH" if operation in {"AttachUserPolicy", "PutUserPolicy"} else "LOW",
    )


class TestInvestigationEngine(unittest.TestCase):
    def setUp(self):
        self.events = InMemoryEventRepository()
        self.assessments = InMemoryAssessmentRepository()

        # 3am untrusted IP + sensitive op = multiple findings, high risk.
        self.event = _make_event(
            event_id="evt-1",
            operation="AttachUserPolicy",
            actor_arn="arn:aws:iam::1:user/alice",
            source_ip="203.0.113.5",
        )
        self.events.save(self.event)

    def _make_engine(self, analyzer):
        return InvestigationEngine(
            event_repository=self.events,
            assessment_repository=self.assessments,
            analyzer=analyzer,
        )

    def test_actor_profile_reflects_analyzer_score(self):
        from aws_tower.analyzer.local_analyzer import LocalAnalyzer

        analyzer = LocalAnalyzer(trusted_networks=["10.0.0.0/8"])
        engine = self._make_engine(analyzer)
        profile = engine.get_actor_profile("arn:aws:iam::1:user/alice")
        # The event is outside business hours, on an untrusted IP, and is
        # a restricted operation. The analyzer should produce a non-zero
        # score; the old code always returned 0 because
        # `event.security.risk_score` was never populated.
        self.assertGreater(profile["risk_score"], 0.0)
        self.assertIn(profile["risk_level"], ("MEDIUM", "HIGH", "CRITICAL"))

    def test_actor_profile_zero_when_no_analyzer(self):
        engine = self._make_engine(analyzer=None)
        profile = engine.get_actor_profile("arn:aws:iam::1:user/alice")
        # No analyzer -> no scoring -> risk_score is 0.0, level is LOW.
        self.assertEqual(profile["risk_score"], 0.0)
        self.assertEqual(profile["risk_level"], "LOW")

    def test_actor_profile_includes_unique_ips_and_operations(self):
        from aws_tower.analyzer.local_analyzer import LocalAnalyzer

        # Add a second event with a different IP and operation.
        self.events.save(
            _make_event(
                event_id="evt-2",
                operation="GetObject",
                actor_arn="arn:aws:iam::1:user/alice",
                source_ip="10.0.0.7",
            )
        )
        engine = self._make_engine(LocalAnalyzer(trusted_networks=["10.0.0.0/8"]))
        profile = engine.get_actor_profile("arn:aws:iam::1:user/alice")
        self.assertEqual(profile["total_events"], 2)
        self.assertIn("203.0.113.5", profile["unique_ips"])
        self.assertIn("10.0.0.7", profile["unique_ips"])
        self.assertIn("AttachUserPolicy", profile["operations_summary"])
        self.assertIn("GetObject", profile["operations_summary"])

    def test_ip_profile_lists_associated_actors(self):
        self.events.save(
            _make_event(
                event_id="evt-3",
                operation="GetObject",
                actor_arn="arn:aws:iam::1:user/bob",
                source_ip="203.0.113.5",
            )
        )
        engine = self._make_engine(analyzer=None)
        profile = engine.get_ip_profile("203.0.113.5")
        self.assertEqual(profile["total_events"], 2)
        self.assertIn("alice", profile["associated_actors"])
        self.assertIn("bob", profile["associated_actors"])


if __name__ == "__main__":
    unittest.main()
