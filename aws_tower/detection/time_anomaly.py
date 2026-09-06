"""Detector for activity outside business hours."""

from __future__ import annotations

from datetime import time

from ..events.models import SecurityEvent
from .base import Detector
from .models import DetectionFinding


class IrregularHourDetector(Detector):
    """Detect activity occurring outside configured business hours."""

    name = "irregular_hour"

    def __init__(
        self,
        start_hour: int = 8,
        end_hour: int = 18,
    ) -> None:
        self._start_hour = start_hour
        self._end_hour = end_hour

    def detect(
        self,
        event: SecurityEvent,
    ) -> DetectionFinding | None:

        event_time = event.event_time.timetz()

        start = time(
            hour=self._start_hour,
            tzinfo=event.event_time.tzinfo,
        )

        end = time(
            hour=self._end_hour,
            tzinfo=event.event_time.tzinfo,
        )

        if self._start_hour > self._end_hour:
            if event_time >= start or event_time < end:
                return None
        else:
            if start <= event_time < end:
                return None

        return DetectionFinding(
            detector=self.name,
            title="Activity outside business hours",
            description=(
                "AWS activity occurred outside "
                "the configured business-hour window."
            ),
            severity="MEDIUM",
            event_id=event.event_id,
            actor_id=(
                event.actor.arn
                or event.actor.user_id
                or event.actor.username
            ),
            resource_id=(
                event.resource.arn
                or event.resource.name
            ),
            evidence={
                "event_time": event.event_time.isoformat(),
                "hour": event.event_time.hour,
                "business_hours": (
                    f"{self._start_hour:02d}:00-"
                    f"{self._end_hour:02d}:00"
                ),
                "operation": event.action.operation,
                "source_ip": event.source_network.ip,
            },
        )
