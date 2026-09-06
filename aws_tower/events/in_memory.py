"""In-memory event repository implementation."""

from __future__ import annotations

from datetime import datetime

from ..risk import actor_matches
from .models import SecurityEvent
from .repository import EventRepository


class InMemoryEventRepository(EventRepository):
    """In-memory implementation of EventRepository."""

    def __init__(self) -> None:
        self._events: dict[str, SecurityEvent] = {}

    @staticmethod
    def _key(event: SecurityEvent) -> str:
        return f"{event.event_time.isoformat()}#{event.event_id}"

    def save(self, event: SecurityEvent) -> None:
        try:
            event.validate()
        except Exception as exc:
            raise ValueError(f"Event validation failed for {event.event_id}: {exc}") from exc
        key = self._key(event)
        self._events[key] = event

    def get(
        self,
        *,
        actor_id: str,
        event_time: datetime,
        event_id: str,
    ) -> SecurityEvent | None:
        del actor_id
        key = f"{event_time.isoformat()}#{event_id}"
        return self._events.get(key)

    def query_by_actor(
        self,
        *,
        actor_id: str,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> list[SecurityEvent]:
        events = [
            event
            for event in self._events.values()
            if actor_matches(event, actor_id)
        ]
        return self._filter_time_range(events, start_time, end_time)

    def query_by_resource(
        self,
        *,
        resource_id: str,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> list[SecurityEvent]:
        events = [
            event
            for event in self._events.values()
            if self._resource_id(event) == resource_id
        ]
        return self._filter_time_range(events, start_time, end_time)

    def query_by_severity(
        self,
        *,
        severity: str,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> list[SecurityEvent]:
        events = [
            event for event in self._events.values() if event.severity == severity
        ]
        return self._filter_time_range(events, start_time, end_time)

    def query_by_source_ip(
        self,
        *,
        ip_address: str,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> list[SecurityEvent]:
        events = [
            event
            for event in self._events.values()
            if event.source_network and event.source_network.ip == ip_address
        ]
        return self._filter_time_range(events, start_time, end_time)

    def query_by_time_range(
        self,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> list[SecurityEvent]:
        return self._filter_time_range(list(self._events.values()), start_time, end_time)

    @staticmethod
    def _actor_id(event: SecurityEvent) -> str:
        return (event.actor.arn or event.actor.user_id or event.actor.username or "unknown")

    @staticmethod
    def _resource_id(event: SecurityEvent) -> str:
        return event.resource.arn or event.resource.name or "unknown"

    @staticmethod
    def _filter_time_range(
        events: list[SecurityEvent],
        start_time: datetime | None,
        end_time: datetime | None,
    ) -> list[SecurityEvent]:
        filtered = events
        if start_time is not None:
            filtered = [event for event in filtered if event.event_time >= start_time]
        if end_time is not None:
            filtered = [event for event in filtered if event.event_time <= end_time]
        return sorted(filtered, key=lambda event: event.event_time)

    def list_all_actors(self) -> list[str]:
        """List all unique actor IDs in the repository."""
        actors = set()
        for event in self._events.values():
            actor_id = self._actor_id(event)
            if actor_id != "unknown":
                actors.add(actor_id)
        return list(actors)
