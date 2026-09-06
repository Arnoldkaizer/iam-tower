"""Behavioral analysis utilities for UEBA detection."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from ..events.models import SecurityEvent


@dataclass
class DownloadActivity:
    actor_identity: str
    window_start: datetime
    window_end: datetime
    events: list[SecurityEvent]

    @property
    def download_count(self) -> int:
        return len(self.events)


class DownloadAggregator:
    """Aggregate successful S3 GetObject events into actor-based time windows."""

    def __init__(self, window_minutes: int = 15):
        if window_minutes <= 0:
            raise ValueError("window_minutes must be greater than zero")

        self.window = timedelta(minutes=window_minutes)

    def aggregate(
        self,
        events: list[SecurityEvent],
    ) -> list[DownloadActivity]:
        downloads = [
            event
            for event in events
            if self._is_download(event)
        ]

        grouped: dict[str, list[SecurityEvent]] = {}

        for event in downloads:
            actor_identity = self._get_actor_identity(event)

            if actor_identity is None:
                continue

            grouped.setdefault(actor_identity, []).append(event)

        activities: list[DownloadActivity] = []

        for actor_identity, actor_events in grouped.items():
            actor_events.sort(key=lambda event: event.event_time)

            activities.extend(
                self._build_windows(
                    actor_identity,
                    actor_events,
                )
            )

        return activities

    @staticmethod
    def _is_download(event: SecurityEvent) -> bool:
        return (
            event.action.operation == "GetObject"
            and event.result.status == "SUCCESS"
        )

    @staticmethod
    def _get_actor_identity(
        event: SecurityEvent,
    ) -> str | None:
        actor = event.actor

        if actor.arn:
            return actor.arn

        if actor.user_id:
            return actor.user_id

        if actor.username:
            return actor.username

        return None

    def _build_windows(
        self,
        actor_identity: str,
        events: list[SecurityEvent],
    ) -> list[DownloadActivity]:
        activities: list[DownloadActivity] = []

        for index, event in enumerate(events):
            window_start = event.event_time
            window_end = window_start + self.window

            window_events = [
                candidate
                for candidate in events[index:]
                if candidate.event_time <= window_end
            ]

            activities.append(
                DownloadActivity(
                    actor_identity=actor_identity,
                    window_start=window_start,
                    window_end=window_end,
                    events=window_events,
                )
            )

        return activities


class BehavioralIncidentSelector:
    """Collapse overlapping activities into distinct behavioral incidents."""

    def select(
        self,
        activities: list[DownloadActivity],
    ) -> list[DownloadActivity]:
        selected: list[DownloadActivity] = []

        grouped: dict[str, list[DownloadActivity]] = {}

        for activity in activities:
            grouped.setdefault(
                activity.actor_identity,
                [],
            ).append(activity)

        for actor_activities in grouped.values():
            actor_activities.sort(
                key=lambda activity: (
                    activity.window_start,
                    -activity.download_count,
                )
            )

            index = 0

            while index < len(actor_activities):
                current = actor_activities[index]

                overlapping = [
                    activity
                    for activity in actor_activities[index:]
                    if activity.window_start <= current.window_end
                ]

                strongest = max(
                    overlapping,
                    key=lambda activity: activity.download_count,
                )

                selected.append(strongest)

                index += len(overlapping)

        selected.sort(
            key=lambda activity: activity.window_start
        )

        return selected
