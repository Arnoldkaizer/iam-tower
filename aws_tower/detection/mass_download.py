"""Detector for mass download activity."""

from __future__ import annotations

from .behavioral import DownloadActivity
from .models import DetectionFinding


class MassDownloadDetector:
    """Detect excessive S3 download activity."""

    name = "mass_download"

    def __init__(self, threshold: int = 20):
        if threshold <= 0:
            raise ValueError("threshold must be greater than zero")

        self.threshold = threshold

    def detect(
        self,
        activity: DownloadActivity,
    ) -> DetectionFinding | None:
        if activity.download_count <= self.threshold:
            return None

        first_event = activity.events[0]

        return DetectionFinding(
            detector=self.name,
            title="Mass download activity detected",
            description=(
                f"Actor {activity.actor_identity} performed "
                f"{activity.download_count} successful S3 downloads "
                f"within a {activity.window_end - activity.window_start} "
                "window."
            ),
            severity="HIGH",
            event_id=first_event.event_id,
            actor_id=activity.actor_identity,
            evidence={
                "download_count": activity.download_count,
                "threshold": self.threshold,
                "window_start": activity.window_start.isoformat(),
                "window_end": activity.window_end.isoformat(),
            },
            metadata={
                "operation": "GetObject",
                "behavior": "mass_download",
            },
        )
