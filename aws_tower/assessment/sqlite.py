"""SQLite-backed assessment repository for cross-process CLI persistence."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from ..detection.models import DetectionFinding
from .models import SecurityAssessment
from .repository import AssessmentRepository


class SQLiteAssessmentRepository(AssessmentRepository):
    """Persist actor assessments and their findings in SQLite."""

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
                CREATE TABLE IF NOT EXISTS assessments (
                    assessment_id TEXT PRIMARY KEY,
                    actor_id TEXT NOT NULL,
                    assessed_at TEXT NOT NULL,
                    score REAL NOT NULL,
                    risk_level TEXT NOT NULL,
                    findings TEXT NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_assessments_actor ON assessments(actor_id)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_assessments_time ON assessments(assessed_at)"
            )

    @staticmethod
    def _decode(row: sqlite3.Row) -> SecurityAssessment:
        findings = [DetectionFinding(**item) for item in json.loads(row["findings"])]
        return SecurityAssessment(
            assessment_id=row["assessment_id"],
            actor_id=row["actor_id"],
            assessed_at=datetime.fromisoformat(row["assessed_at"]),
            score=float(row["score"]),
            risk_level=row["risk_level"],
            findings=findings,
        )

    def save(self, assessment: SecurityAssessment) -> None:
        with self._connection() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO assessments (
                    assessment_id, actor_id, assessed_at, score, risk_level, findings
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    assessment.assessment_id,
                    assessment.actor_id,
                    assessment.assessed_at.isoformat(),
                    assessment.score,
                    assessment.risk_level,
                    json.dumps([finding.__dict__ for finding in assessment.findings]),
                ),
            )

    def get(self, *, assessment_id: str) -> SecurityAssessment | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM assessments WHERE assessment_id = ?", (assessment_id,)
            ).fetchone()
        return self._decode(row) if row else None

    @staticmethod
    def _time_filter(
        start_time: datetime | None, end_time: datetime | None
    ) -> tuple[str, list[str]]:
        clauses: list[str] = []
        values: list[str] = []
        if start_time is not None:
            clauses.append("assessed_at >= ?")
            values.append(start_time.isoformat())
        if end_time is not None:
            clauses.append("assessed_at <= ?")
            values.append(end_time.isoformat())
        return (f" AND {' AND '.join(clauses)}" if clauses else "", values)

    def query_by_actor(self, *, actor_id: str, start_time: datetime | None = None, end_time: datetime | None = None) -> list[SecurityAssessment]:
        time_clause, values = self._time_filter(start_time, end_time)
        with self._connection() as connection:
            rows = connection.execute(
                f"SELECT * FROM assessments WHERE actor_id = ?{time_clause} ORDER BY assessed_at",
                (actor_id, *values),
            ).fetchall()
        return [self._decode(row) for row in rows]

    def get_latest_by_actor(self, actor_id: str) -> SecurityAssessment | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM assessments WHERE actor_id = ? ORDER BY assessed_at DESC LIMIT 1",
                (actor_id,),
            ).fetchone()
        return self._decode(row) if row else None

    def list_latest(self, limit: int = 10) -> list[SecurityAssessment]:
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT assessment_id, assessed_at FROM (
                    SELECT assessment_id,
                           assessed_at,
                           ROW_NUMBER() OVER (
                               PARTITION BY actor_id ORDER BY assessed_at DESC
                           ) AS row_number
                    FROM assessments
                )
                WHERE row_number = 1
                ORDER BY assessed_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        results = [self.get(assessment_id=row["assessment_id"]) for row in rows]
        return [assessment for assessment in results if assessment is not None]
