"""Security assessment service for TOWER."""

from __future__ import annotations

from collections.abc import Iterable

from ..detection.behavioral_engine import (
    BehavioralDetectionEngine,
)
from ..detection.correlation import (
    CorrelationResult,
    RiskCorrelator,
)
from ..detection.detectors import build_default_registry
from ..detection.engine import DetectionEngine
from ..detection.models import DetectionFinding
from ..events.models import SecurityEvent


class SecurityAssessmentService:
    """Run event and behavioral detection and correlate the findings."""

    def __init__(
        self,
        detection_engine: DetectionEngine,
        behavioral_engine: BehavioralDetectionEngine,
        correlator: RiskCorrelator,
    ) -> None:
        self._detection_engine = detection_engine
        self._behavioral_engine = behavioral_engine
        self._correlator = correlator

    def assess(
        self,
        events: Iterable[SecurityEvent],
    ) -> CorrelationResult:
        events = list(events)

        findings: list[DetectionFinding] = []

        for event in events:
            findings.extend(
                self._detection_engine.analyze(event)
            )

        findings.extend(
            self._behavioral_engine.analyze(events)
        )

        return self._correlator.correlate(findings)


def build_security_assessment_service(
    trusted_networks: Iterable[str],
    *,
    business_start_hour: int = 8,
    business_end_hour: int = 18,
) -> SecurityAssessmentService:
    """Build the default Security Tower assessment service."""

    registry = build_default_registry(
        list(trusted_networks),
        business_start_hour=business_start_hour,
        business_end_hour=business_end_hour,
    )

    detection_engine = DetectionEngine(registry)
    behavioral_engine = BehavioralDetectionEngine()
    correlator = RiskCorrelator()

    return SecurityAssessmentService(
        detection_engine=detection_engine,
        behavioral_engine=behavioral_engine,
        correlator=correlator,
    )
