"""Tests for AlertManager dispatch path."""

import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock

from aws_tower.alerting.alerts import Alert, AlertManager
from aws_tower.assessment.models import SecurityAssessment
from aws_tower.detection.models import DetectionFinding


class TestDispatchAlertAcceptsDict(unittest.TestCase):
    def test_dispatch_alert_accepts_dict(self):
        sink = MagicMock()
        manager = AlertManager(sinks=[sink], min_risk_score=0.0)
        payload = {
            "actor_id": "alice",
            "risk_score": 7.5,
            "risk_level": "HIGH",
            "message": "synthetic alert",
            "threats": [{"rule_id": "r1", "title": "t1", "severity": "HIGH"}],
        }
        outcomes = manager.dispatch_alert(payload)
        sink.send_alert.assert_called_once()
        sent = sink.send_alert.call_args.args[0]
        self.assertIsInstance(sent, Alert)
        self.assertEqual(sent.actor_id, "alice")
        self.assertEqual(sent.risk_score, 7.5)
        self.assertEqual(sent.risk_level, "HIGH")
        self.assertEqual(sent.findings, [{"rule_id": "r1", "title": "t1", "severity": "HIGH"}])
        self.assertEqual(outcomes, [(sink, True, None)])

    def test_dispatch_alert_passes_alert_unchanged(self):
        sink = MagicMock()
        manager = AlertManager(sinks=[sink], min_risk_score=0.0)
        alert = Alert(
            alert_id="a-1",
            actor_id="bob",
            risk_score=4.0,
            risk_level="MEDIUM",
            message="hi",
            timestamp=datetime.now(timezone.utc),
        )
        manager.dispatch_alert(alert)
        sink.send_alert.assert_called_once_with(alert)


class TestProcessAssessmentEndToEnd(unittest.TestCase):
    def test_process_assessment_dispatches_when_above_threshold(self):
        sink = MagicMock()
        manager = AlertManager(sinks=[sink], min_risk_score=0.0)
        finding = DetectionFinding(
            detector="d1",
            event_id="e1",
            title="t",
            description="d",
            severity="HIGH",
        )
        assessment = SecurityAssessment(
            assessment_id="asm-1",
            actor_id="alice",
            assessed_at=datetime.now(timezone.utc),
            score=6.0,
            risk_level="HIGH",
            findings=[finding],
        )
        result = manager.process_assessment(assessment)
        self.assertIsNotNone(result)
        sink.send_alert.assert_called_once()

    def test_process_assessment_skips_below_threshold(self):
        sink = MagicMock()
        manager = AlertManager(sinks=[sink], min_risk_score=8.0)
        assessment = SecurityAssessment(
            assessment_id="asm-2",
            actor_id="alice",
            assessed_at=datetime.now(timezone.utc),
            score=2.0,
            risk_level="LOW",
            findings=[],
        )
        result = manager.process_assessment(assessment)
        self.assertIsNone(result)
        sink.send_alert.assert_not_called()


if __name__ == "__main__":
    unittest.main()
