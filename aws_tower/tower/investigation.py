"""Security investigation engine."""

from __future__ import annotations

from typing import Any, Protocol

from ..assessment.repository import AssessmentRepository
from ..events.models import SecurityEvent
from ..events.repository import EventRepository
from ..risk import clamp_risk_score, score_to_risk_level


class _ActorRiskScorer(Protocol):
    """Minimal interface the investigation engine needs from the analyzer.

    A full `LocalAnalyzer` satisfies this; tests can pass a stub.
    """

    def risk_score_for(self, actor_id: str, events: list[SecurityEvent]) -> float:
        ...


class InvestigationEngine:
    """Investigate security events and assessments for actors and IPs."""

    def __init__(
        self,
        event_repository: EventRepository,
        assessment_repository: AssessmentRepository,
        analyzer: _ActorRiskScorer | None = None,
    ) -> None:
        self.event_repo = event_repository
        self.assessment_repo = assessment_repository
        # If no analyzer is injected, the profile falls back to 0.0 risk
        # — but that scenario is unlikely in normal use; the orchestrator
        # always wires one in.
        self._analyzer = analyzer

    def get_actor_profile(self, actor_id: str) -> dict[str, Any]:
        """Get a profile for an actor including events and risk.

        Risk is computed by the local analyzer over the actor's events —
        we deliberately do NOT read `event.security.risk_score`, because
        `LocalIngestion` never populates that field and any old Bedrock
        data left in the field would silently appear here.
        """
        events = self.event_repo.query_by_actor(actor_id=actor_id)

        unique_ips: set[str] = set()
        operations: list[str] = []

        for event in events:
            if event.source_network and event.source_network.ip:
                unique_ips.add(event.source_network.ip)
            if event.action and event.action.operation:
                operations.append(event.action.operation)

        if self._analyzer is not None:
            try:
                risk_score = clamp_risk_score(self._analyzer.risk_score_for(actor_id, events))
            except Exception:
                risk_score = 0.0
        else:
            risk_score = 0.0

        return {
            "total_events": len(events),
            "risk_score": round(risk_score, 1),
            "risk_level": score_to_risk_level(risk_score),
            "unique_ips": sorted(unique_ips),
            "operations_summary": sorted(set(operations))[:20],
        }

    def get_ip_profile(self, ip_address: str) -> dict[str, Any]:
        """Get a profile for an IP address."""
        events = self.event_repo.query_by_source_ip(ip_address=ip_address)

        associated_actors = set()
        services = set()

        for event in events:
            actor_id = event.actor.username or event.actor.arn or event.actor.user_id or "unknown"
            associated_actors.add(actor_id)
            if event.source and event.source.service:
                services.add(event.source.service)

        return {
            "total_events": len(events),
            "associated_actors": sorted(associated_actors),
            "services_accessed": sorted(services),
        }

    def query_timeline(
        self,
        actor_id: str | None = None,
        ip_address: str | None = None,
    ) -> list[SecurityEvent]:
        """Query events for timeline view."""
        if actor_id:
            return self.event_repo.query_by_actor(actor_id=actor_id)
        if ip_address:
            return self.event_repo.query_by_source_ip(ip_address=ip_address)
        return []
