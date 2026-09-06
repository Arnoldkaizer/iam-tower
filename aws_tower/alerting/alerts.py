"""Security alert models and sinks."""

from __future__ import annotations

import json
import urllib.request
from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..assessment.models import SecurityAssessment


@dataclass
class Alert:
    """Security Alert object produced by Security Tower."""

    alert_id: str
    actor_id: str
    risk_score: float
    risk_level: str
    message: str
    timestamp: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    findings: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert alert to a serializable dictionary."""

        return {
            "alert_id": self.alert_id,
            "actor_id": self.actor_id,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "message": self.message,
            "timestamp": self.timestamp.isoformat(),
            "findings": self.findings,
            "metadata": self.metadata,
        }


class AlertSink(ABC):
    """Abstract base class for security alert dispatchers."""

    @abstractmethod
    def send_alert(self, alert: Alert) -> None:
        """Send or record a security alert."""
        pass


class ConsoleAlertSink(AlertSink):
    """Output alerts to standard console using formatted text."""

    def send_alert(self, alert: Alert) -> None:

        color_prefix = "[HIGH/CRITICAL]"

        if alert.risk_level == "MEDIUM":
            color_prefix = "[MEDIUM]"
        elif alert.risk_level == "LOW":
            color_prefix = "[LOW]"

        print(f"\n{color_prefix} SECURITY TOWER ALERT - {alert.alert_id}")
        print(f"Actor: {alert.actor_id}")
        print(f"Risk Score: {alert.risk_score}/10 ({alert.risk_level})")
        print(f"Summary: {alert.message}")

        if alert.findings:
            print(f"Findings Count: {len(alert.findings)}")

            for idx, finding in enumerate(alert.findings, 1):
                rule = finding.get("rule_id", finding.get("detector", "Finding"))
                title = finding.get("title", "")
                sev = finding.get("severity", "")
                print(f"  {idx}. [{sev}] {rule}: {title}")

        print("-" * 50)


class JsonFileAlertSink(AlertSink):
    """Write alerts to a local JSON Lines (.jsonl) log file."""

    def __init__(self, file_path: str | Path) -> None:
        import threading
        self._file_path = Path(file_path)
        self._file_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def send_alert(self, alert: Alert) -> None:
        with self._lock, open(self._file_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(alert.to_dict()) + "\n")


class SnsAlertSink(AlertSink):
    """Dispatch alerts to an AWS SNS Topic."""

    def __init__(
        self,
        topic_arn: str,
        boto3_session: Any | None = None,
    ) -> None:
        self._topic_arn = topic_arn
        self._boto3_session = boto3_session

    def send_alert(self, alert: Alert) -> None:
        import boto3

        session = self._boto3_session or boto3.Session()
        sns = session.client("sns")

        subject = f"Security Tower Alert: {alert.actor_id} [{alert.risk_level}]"

        sns.publish(
            TopicArn=self._topic_arn,
            Subject=subject[:100],  # SNS Subject max length is 100
            Message=json.dumps(alert.to_dict(), indent=2),
        )


class WebhookAlertSink(AlertSink):
    """Dispatch alerts as HTTP POST requests to a custom webhook URL."""

    def __init__(
        self,
        webhook_url: str,
        headers: dict[str, str] | None = None,
    ) -> None:
        self._webhook_url = webhook_url
        self._headers = headers or {"Content-Type": "application/json"}

    def send_alert(self, alert: Alert) -> None:
        data = json.dumps(alert.to_dict()).encode("utf-8")
        req = urllib.request.Request(
            self._webhook_url,
            data=data,
            headers=self._headers,
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=5):
                pass
        except Exception as exc:
            import logging
            logging.getLogger(__name__).warning("Webhook alert dispatch failed: %s", exc)


class AlertManager:
    """Filter assessments and dispatch security alerts to registered sinks."""

    def __init__(
        self,
        sinks: Iterable[AlertSink] = (),
        *,
        min_risk_score: float = 4.0,
        min_risk_level: str = "MEDIUM",
    ) -> None:
        self._sinks: list[AlertSink] = list(sinks)
        self._min_risk_score = min_risk_score
        self._min_risk_level = min_risk_level.upper()

    def add_sink(self, sink: AlertSink) -> None:
        self._sinks.append(sink)

    def process_assessment(
        self,
        assessment: SecurityAssessment,
    ) -> Alert | None:
        """Evaluate a security assessment and generate an alert if it exceeds thresholds."""

        score = getattr(assessment, "score", getattr(assessment, "risk_score", 0.0))

        if score < self._min_risk_score:
            return None

        # Check severity level
        level_weight = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

        current_level_weight = level_weight.get(assessment.risk_level, 1)

        min_level_weight = level_weight.get(self._min_risk_level, 2)

        if current_level_weight < min_level_weight:
            return None

        findings_data = [
            {
                "rule_id": getattr(f, "detector", getattr(f, "rule_id", "Finding")),
                "title": f.title,
                "severity": f.severity,
                "description": f.description,
                "event_id": f.event_id,
            }
            for f in assessment.findings
        ]

        alert = Alert(
            alert_id=assessment.assessment_id,
            actor_id=assessment.actor_id,
            risk_score=score,
            risk_level=assessment.risk_level,
            message=(
                f"Security assessment for actor {assessment.actor_id} "
                f"resulted in {assessment.risk_level} risk score ({score})."
            ),
            timestamp=assessment.assessed_at,
            findings=findings_data,
        )

        self.dispatch_alert(alert)

        return alert

    def dispatch_alert(
        self, alert: Alert | dict[str, Any]
    ) -> list[tuple[AlertSink, bool, str | None]]:
        """Dispatch a security alert to all configured alert sinks and track dispatch outcomes.

        Accepts either an `Alert` instance or a plain `dict` (for callers
        that don't want to construct the dataclass). Dicts are normalized
        into an `Alert`; missing fields fall back to safe defaults.
        """
        if not isinstance(alert, Alert):
            alert = Alert(
                alert_id=str(alert.get("alert_id", "")),
                actor_id=str(alert.get("actor_id", "unknown")),
                risk_score=float(alert.get("risk_score", 0.0)),
                risk_level=str(alert.get("risk_level", "LOW")),
                message=str(alert.get("message", "Security Tower alert")),
                findings=list(alert.get("findings", alert.get("threats", []))),
                metadata=dict(alert.get("metadata", {})),
            )

        outcomes: list[tuple[AlertSink, bool, str | None]] = []

        for sink in self._sinks:
            try:
                sink.send_alert(alert)
                outcomes.append((sink, True, None))
            except Exception as exc:
                outcomes.append((sink, False, str(exc)))

        return outcomes
