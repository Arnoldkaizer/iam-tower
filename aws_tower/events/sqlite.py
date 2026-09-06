"""SQLite-backed event repository for cross-process CLI persistence."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

from .models import (
    Action,
    Actor,
    EventResult,
    EventSource,
    Resource,
    SecurityAnalysis,
    SecurityEvent,
    SourceNetwork,
)
from .repository import EventRepository


class SQLiteEventRepository(EventRepository):
    """Persist normalized events in a local SQLite database."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    @contextmanager
    def _connection(self):
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connection() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    event_key TEXT PRIMARY KEY,
                    event_id TEXT NOT NULL,
                    event_time TEXT NOT NULL,
                    actor_id TEXT NOT NULL,
                    actor_arn TEXT,
                    actor_user_id TEXT,
                    actor_username TEXT,
                    resource_id TEXT,
                    source_ip TEXT,
                    severity TEXT NOT NULL,
                    payload TEXT NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_actor ON events(actor_id)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_time ON events(event_time)"
            )

    @staticmethod
    def _key(event: SecurityEvent) -> str:
        return f"{event.event_time.isoformat()}#{event.event_id}"

    @staticmethod
    def _actor_id(event: SecurityEvent) -> str:
        return event.actor.arn or event.actor.user_id or event.actor.username or "unknown"

    @staticmethod
    def _resource_id(event: SecurityEvent) -> str:
        return event.resource.arn or event.resource.name or "unknown"

    @staticmethod
    def _serialize(event: SecurityEvent) -> str:
        payload: dict[str, Any] = {
            "event_id": event.event_id,
            "event_time": event.event_time.isoformat(),
            "source": event.source.__dict__,
            "actor": event.actor.__dict__,
            "source_network": event.source_network.__dict__,
            "action": event.action.__dict__,
            "resource": event.resource.__dict__,
            "result": event.result.__dict__,
            "severity": event.severity,
            "event_version": event.event_version,
            "ingested_at": event.ingested_at.isoformat(),
            "security": event.security.__dict__,
            "metadata": event.metadata,
        }
        return json.dumps(payload)

    @staticmethod
    def _deserialize(payload: str) -> SecurityEvent:
        data = json.loads(payload)
        return SecurityEvent(
            event_id=data["event_id"],
            event_time=datetime.fromisoformat(data["event_time"]),
            source=EventSource(**data["source"]),
            actor=Actor(**data["actor"]),
            source_network=SourceNetwork(**data["source_network"]),
            action=Action(**data["action"]),
            resource=Resource(**data["resource"]),
            result=EventResult(**data["result"]),
            severity=data["severity"],
            event_version=data.get("event_version", "1.0"),
            ingested_at=datetime.fromisoformat(data["ingested_at"]),
            security=SecurityAnalysis(**data.get("security", {})),
            metadata=data.get("metadata", {}),
        )

    def save(self, event: SecurityEvent) -> None:
        event.validate()
        actor_id = self._actor_id(event)
        with self._connection() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO events (
                    event_key, event_id, event_time, actor_id, actor_arn,
                    actor_user_id, actor_username, resource_id, source_ip,
                    severity, payload
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    self._key(event),
                    event.event_id,
                    event.event_time.isoformat(),
                    actor_id,
                    event.actor.arn,
                    event.actor.user_id,
                    event.actor.username,
                    self._resource_id(event),
                    event.source_network.ip,
                    event.severity,
                    self._serialize(event),
                ),
            )

    def get(self, *, actor_id: str, event_time: datetime, event_id: str) -> SecurityEvent | None:
        del actor_id
        with self._connection() as connection:
            row = connection.execute(
                "SELECT payload FROM events WHERE event_key = ?",
                (f"{event_time.isoformat()}#{event_id}",),
            ).fetchone()
        return self._deserialize(row["payload"]) if row else None

    def _query(self, where: str = "", values: tuple[Any, ...] = ()) -> list[SecurityEvent]:
        with self._connection() as connection:
            rows = connection.execute(
                f"SELECT payload FROM events {where} ORDER BY event_time", values
            ).fetchall()
        return [self._deserialize(row["payload"]) for row in rows]

    @staticmethod
    def _time_filter(
        start_time: datetime | None, end_time: datetime | None
    ) -> tuple[str, list[Any]]:
        clauses: list[str] = []
        values: list[Any] = []
        if start_time is not None:
            clauses.append("event_time >= ?")
            values.append(start_time.isoformat())
        if end_time is not None:
            clauses.append("event_time <= ?")
            values.append(end_time.isoformat())
        return (f"WHERE {' AND '.join(clauses)}" if clauses else "", values)

    def query_by_actor(self, *, actor_id: str, start_time: datetime | None = None, end_time: datetime | None = None) -> list[SecurityEvent]:
        time_where, values = self._time_filter(start_time, end_time)
        actor_clause = "actor_id = ? OR actor_arn = ? OR actor_user_id = ? OR actor_username = ?"
        where = f"WHERE ({actor_clause})"
        if time_where:
            where += " AND " + time_where.removeprefix("WHERE ")
        return self._query(where, (actor_id, actor_id, actor_id, actor_id, *values))

    def query_by_resource(self, *, resource_id: str, start_time: datetime | None = None, end_time: datetime | None = None) -> list[SecurityEvent]:
        time_where, values = self._time_filter(start_time, end_time)
        where = "WHERE resource_id = ?"
        if time_where:
            where += " AND " + time_where.removeprefix("WHERE ")
        return self._query(where, (resource_id, *values))

    def query_by_severity(self, *, severity: str, start_time: datetime | None = None, end_time: datetime | None = None) -> list[SecurityEvent]:
        time_where, values = self._time_filter(start_time, end_time)
        where = "WHERE severity = ?"
        if time_where:
            where += " AND " + time_where.removeprefix("WHERE ")
        return self._query(where, (severity, *values))

    def query_by_source_ip(self, *, ip_address: str, start_time: datetime | None = None, end_time: datetime | None = None) -> list[SecurityEvent]:
        time_where, values = self._time_filter(start_time, end_time)
        where = "WHERE source_ip = ?"
        if time_where:
            where += " AND " + time_where.removeprefix("WHERE ")
        return self._query(where, (ip_address, *values))

    def query_by_time_range(self, start_time: datetime | None = None, end_time: datetime | None = None) -> list[SecurityEvent]:
        where, values = self._time_filter(start_time, end_time)
        return self._query(where, tuple(values))

    def list_all_actors(self) -> list[str]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT DISTINCT actor_id FROM events WHERE actor_id != 'unknown' ORDER BY actor_id"
            ).fetchall()
        return [row["actor_id"] for row in rows]
