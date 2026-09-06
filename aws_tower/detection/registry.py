"""Event-level security detectors registry."""

from __future__ import annotations

from collections.abc import Iterable

from .base import Detector


class DetectorRegistry:
    """Stores and manages registered security detectors."""

    def __init__(
        self,
        detectors: Iterable[Detector] = (),
    ) -> None:
        self._detectors = list(detectors)

    def register(
        self,
        detector: Detector,
    ) -> None:
        self._detectors.append(detector)

    def detectors(self) -> list[Detector]:
        return list(self._detectors)
