"""Behavioral/UEBA detection engine for multi-event analysis."""

from __future__ import annotations

from collections.abc import Iterable

from ..events.models import SecurityEvent
from .behavioral import (
    BehavioralIncidentSelector,
    DownloadActivity,
    DownloadAggregator,
)
from .mass_download import MassDownloadDetector
from .models import DetectionFinding


class BehavioralDetectionEngine:
    """Run multi-event behavioral security detectors."""

    def __init__(
        self,
        aggregator: DownloadAggregator | None = None,
        incident_selector: BehavioralIncidentSelector | None = None,
        detectors: Iterable[MassDownloadDetector] = (),
    ) -> None:
        self._aggregator = (
            aggregator
            if aggregator is not None
            else DownloadAggregator()
        )

        self._incident_selector = (
            incident_selector
            if incident_selector is not None
            else BehavioralIncidentSelector()
        )

        self._detectors = list(detectors)

        if not self._detectors:
            self._detectors = [
                MassDownloadDetector()
            ]

    def analyze(
        self,
        events: list[SecurityEvent],
    ) -> list[DetectionFinding]:
        activities = self._aggregator.aggregate(events)

        incidents = self._incident_selector.select(
            activities
        )

        findings: list[DetectionFinding] = []

        for incident in incidents:
            findings.extend(
                self._detect_incident(incident)
            )

        return findings

    def _detect_incident(
        self,
        activity: DownloadActivity,
    ) -> list[DetectionFinding]:
        findings: list[DetectionFinding] = []

        for detector in self._detectors:
            finding = detector.detect(activity)

            if finding is not None:
                findings.append(finding)

        return findings
