"""Base detector interface for security event analysis."""

from __future__ import annotations

from abc import ABC, abstractmethod

from aws_tower.events.models import SecurityEvent

from .models import DetectionFinding


class Detector(ABC):
    """Base interface for all security detectors."""

    name: str

    @abstractmethod
    def detect(
        self,
        event: SecurityEvent,
    ) -> DetectionFinding | None:
        """
        Analyze a security event.

        Return a DetectionFinding when suspicious
        activity is detected, otherwise return None.
        """
        raise NotImplementedError
