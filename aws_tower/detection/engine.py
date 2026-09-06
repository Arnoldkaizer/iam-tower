"""Security event detection engine."""

from __future__ import annotations

from collections.abc import Iterable

from ..events.models import SecurityEvent
from .base import Detector
from .models import DetectionFinding
from .registry import DetectorRegistry


class DetectionEngine:
    """Runs registered security detectors against events."""

    def __init__(
        self,
        detectors: Iterable[Detector] | DetectorRegistry = (),
    ) -> None:
        if isinstance(detectors, DetectorRegistry):
            self._registry = detectors
        else:
            self._registry = DetectorRegistry(detectors)

    def analyze(
        self,
        event: SecurityEvent,
    ) -> list[DetectionFinding]:
        findings: list[DetectionFinding] = []

        for detector in self._registry.detectors():
            finding = detector.detect(event)

            if finding is not None:
                findings.append(finding)

        return findings
