import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from aws_tower.assessment.models import SecurityAssessment
from aws_tower.assessment.sqlite import SQLiteAssessmentRepository
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
from aws_tower.events.sqlite import SQLiteEventRepository


class TestSQLiteRepositories(unittest.TestCase):
    def test_event_round_trip_across_repository_instances(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tower.db"
            event = SecurityEvent(
                event_id="evt-1",
                event_time=datetime(2026, 9, 1, tzinfo=timezone.utc),
                source=EventSource("aws", "iam", "cloudtrail", "AwsApiCall", "GetUser"),
                actor=Actor("IAMUser", username="alice", arn="arn:aws:iam::1:user/alice"),
                source_network=SourceNetwork(ip="203.0.113.10"),
                action=Action("read", "GetUser", True),
                resource=Resource("IAMUser", name="alice"),
                result=EventResult("SUCCESS"),
                severity="LOW",
            )
            SQLiteEventRepository(path).save(event)

            restored = SQLiteEventRepository(path).query_by_actor(actor_id="alice")

            self.assertEqual(len(restored), 1)
            self.assertEqual(restored[0].event_id, "evt-1")
            self.assertEqual(restored[0].source_network.ip, "203.0.113.10")

    def test_assessment_round_trip_across_repository_instances(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tower.db"
            assessment = SecurityAssessment(
                assessment_id="assessment-1",
                actor_id="alice",
                assessed_at=datetime(2026, 9, 1, tzinfo=timezone.utc),
                score=8.0,
                risk_level="HIGH",
                findings=[
                    DetectionFinding(
                        detector="test",
                        title="Test finding",
                        description="Test",
                        severity="HIGH",
                        event_id="evt-1",
                    )
                ],
            )
            SQLiteAssessmentRepository(path).save(assessment)

            restored = SQLiteAssessmentRepository(path).get_latest_by_actor("alice")

            self.assertIsNotNone(restored)
            self.assertEqual(restored.score, 8.0)
            self.assertEqual(restored.findings[0].detector, "test")


if __name__ == "__main__":
    unittest.main()
