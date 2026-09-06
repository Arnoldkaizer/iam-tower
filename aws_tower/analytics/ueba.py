"""User & Entity Behavior Analytics (UEBA) for identity analytics."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import ClassVar

from ..detection.base import Detector
from ..detection.models import DetectionFinding
from ..events.models import SecurityEvent
from ..risk import actor_matches


@dataclass
class UserBaseline:
    """Operating baseline for an individual IAM user or role."""

    actor_id: str
    known_ips: set[str] = field(default_factory=set)
    known_services: set[str] = field(default_factory=set)
    known_regions: set[str] = field(default_factory=set)
    first_time_actions: set[str] = field(default_factory=set)


# Time window used for the "impossible travel" detector.
IMPOSSIBLE_TRAVEL_WINDOW = timedelta(minutes=15)


class IdentityAnalyticsEngine(Detector):
    """UEBA Detector identifying anomalous activity spikes, escalation, and region hopping.

    Two public entry points:
    - `build_baselines(events)` — one-time, before analysis. Builds per-actor
      baselines from the historical event set.
    - `detect_for_actor(actor_id, events, baselines, recent_events)` — used
      during per-actor analysis. Takes the pre-built baselines and a
      per-actor recent-events view so it never mutates shared state.

    The legacy `detect(event)` method is preserved for backward compatibility
    but new callers should use `detect_for_actor` for predictable, order-
    independent behavior.
    """

    name = "identity_analytics"

    SENSITIVE_ACTIONS: ClassVar[set[str]] = {
        "AttachUserPolicy",
        "AttachGroupPolicy",
        "AttachRolePolicy",
        "PutUserPolicy",
        "PutGroupPolicy",
        "PutRolePolicy",
        "CreateAccessKey",
        "UpdateAccessKey",
        "CreateLoginProfile",
        "UpdateAssumeRolePolicy",
    }

    def __init__(self) -> None:
        self._baselines: dict[str, UserBaseline] = {}
        self._event_history: list[SecurityEvent] = []

    def build_baselines(self, historical_events: list[SecurityEvent]) -> None:
        """Compute per-actor baselines from a batch of historical events.

        This is intended to be called once per analysis batch. It overwrites
        any previously built baselines — call `reset_state` first if you
        want to start from scratch.
        """
        for event in historical_events:
            actor = self._actor_id(event)
            if not actor:
                continue

            if actor not in self._baselines:
                self._baselines[actor] = UserBaseline(actor_id=actor)

            baseline = self._baselines[actor]

            if event.source_network and event.source_network.ip:
                baseline.known_ips.add(event.source_network.ip)
            if event.source and event.source.service:
                baseline.known_services.add(event.source.service)
            if event.resource and event.resource.region:
                baseline.known_regions.add(event.resource.region)
            if event.action and event.action.operation:
                baseline.first_time_actions.add(event.action.operation)

    def detect_for_actor(
        self,
        actor_id: str,
        events: list[SecurityEvent],
        baselines: dict[str, UserBaseline],
        recent_events_by_actor: dict[str, list[SecurityEvent]] | None = None,
    ) -> list[DetectionFinding]:
        """Run UEBA checks for one actor over a sorted batch of events.

        `events` should be the events belonging to this actor, sorted by
        time. The function returns findings without mutating any shared
        state — `baselines` and `recent_events_by_actor` are read-only.
        """
        if not actor_id or not events:
            return []

        baseline = baselines.get(actor_id) or UserBaseline(actor_id=actor_id)
        # Local copies we update *as we scan* so subsequent events in the
        # same batch can see prior events from this actor. We do NOT write
        # back to the caller's `baselines` dict.
        seen_actions: set[str] = set(baseline.first_time_actions)
        recent: list[SecurityEvent] = list(
            (recent_events_by_actor or {}).get(actor_id, [])
        )

        findings: list[DetectionFinding] = []

        for event in events:
            if not actor_matches(event, actor_id):
                continue

            operation = event.action.operation if event.action else ""
            region = event.resource.region if event.resource else ""

            finding: DetectionFinding | None = None

            # 1. First-time sensitive action against the (locally grown)
            # seen-action set so multiple first-time actions in the same
            # batch all fire.
            if operation in self.SENSITIVE_ACTIONS and operation not in seen_actions:
                finding = DetectionFinding(
                    detector="ueba_privilege_escalation",
                    title="First-Time Sensitive IAM Action Executed",
                    description=(
                        f"Actor {actor_id} executed sensitive privilege "
                        f"escalation action '{operation}' for the first time."
                    ),
                    severity="HIGH",
                    event_id=event.event_id,
                    actor_id=actor_id,
                    evidence={
                        "operation": operation,
                        "actor": actor_id,
                        "reason": "Action absent from historical baseline.",
                    },
                )

            # 2. Impossible travel: distinct region within the rolling window.
            if finding is None and region:
                cutoff = event.event_time - IMPOSSIBLE_TRAVEL_WINDOW
                recent = [e for e in recent if e.event_time >= cutoff]
                recent_regions = {
                    e.resource.region
                    for e in recent
                    if e.resource and e.resource.region
                }
                if recent_regions and region not in recent_regions:
                    finding = DetectionFinding(
                        detector="ueba_impossible_travel",
                        title="Rapid Multi-Region Access (Impossible Travel)",
                        description=(
                            f"Actor {actor_id} performed actions across "
                            f"distinct AWS regions ({sorted(recent_regions)} "
                            f"and {region}) within "
                            f"{int(IMPOSSIBLE_TRAVEL_WINDOW.total_seconds() // 60)} minutes."
                        ),
                        severity="HIGH",
                        event_id=event.event_id,
                        actor_id=actor_id,
                        evidence={
                            "current_region": region,
                            "recent_regions": sorted(recent_regions),
                        },
                    )

            if finding is not None:
                findings.append(finding)

            if operation:
                seen_actions.add(operation)
            recent.append(event)
            # `_seen_actions` is a local copy; we deliberately don't write
            # to the caller's `baselines` dict, so this method is
            # idempotent across actors.

        return findings

    # --- Legacy single-event entry point ---------------------------------

    def detect(self, event: SecurityEvent) -> DetectionFinding | None:
        """Legacy single-event detect. Mutates the engine's internal state.

        Prefer `detect_for_actor` for new code — this entry point is
        preserved for backward compatibility with callers that drive
        detection one event at a time.
        """
        actor = self._actor_id(event)
        if not actor:
            return None

        if actor not in self._baselines:
            self._baselines[actor] = UserBaseline(actor_id=actor)

        baseline = self._baselines[actor]

        operation = event.action.operation if event.action else ""
        region = event.resource.region if event.resource else ""
        ip = event.source_network.ip if event.source_network else ""

        finding: DetectionFinding | None = None

        if operation in self.SENSITIVE_ACTIONS and operation not in baseline.first_time_actions:
            finding = DetectionFinding(
                detector="ueba_privilege_escalation",
                title="First-Time Sensitive IAM Action Executed",
                description=(
                    f"Actor {actor} executed sensitive privilege "
                    f"escalation action '{operation}' for the first time."
                ),
                severity="HIGH",
                event_id=event.event_id,
                actor_id=actor,
                evidence={
                    "operation": operation,
                    "actor": actor,
                    "reason": "Action absent from historical baseline.",
                },
            )

        if finding is None and region:
            recent_cutoff = event.event_time - IMPOSSIBLE_TRAVEL_WINDOW
            self._event_history = [e for e in self._event_history if e.event_time >= recent_cutoff]
            recent_events = [
                e for e in self._event_history
                if actor_matches(e, actor)
                and e.event_time >= recent_cutoff
            ]
            recent_regions = {
                e.resource.region
                for e in recent_events
                if e.resource and e.resource.region
            }
            if recent_regions and region not in recent_regions:
                finding = DetectionFinding(
                    detector="ueba_impossible_travel",
                    title="Rapid Multi-Region Access (Impossible Travel)",
                    description=(
                        f"Actor {actor} performed actions across distinct "
                        f"AWS regions ({sorted(recent_regions)} and {region}) "
                        f"within {int(IMPOSSIBLE_TRAVEL_WINDOW.total_seconds() // 60)} minutes."
                    ),
                    severity="HIGH",
                    event_id=event.event_id,
                    actor_id=actor,
                    evidence={
                        "current_region": region,
                        "recent_regions": sorted(recent_regions),
                    },
                )

        if ip:
            baseline.known_ips.add(ip)
        if region:
            baseline.known_regions.add(region)
        if operation:
            baseline.first_time_actions.add(operation)
        self._event_history.append(event)

        return finding

    def reset_state(self) -> None:
        """Clear per-actor state. Safe to call between analysis runs."""
        self._baselines.clear()
        self._event_history.clear()

    @staticmethod
    def _actor_id(event: SecurityEvent) -> str:
        return event.actor.username or event.actor.user_id or event.actor.arn or ""
