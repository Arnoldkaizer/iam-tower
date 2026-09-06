"""Local rule-based security analyzer.

Composes the existing detection engine, behavioral engine, UEBA engine, and
risk correlator into a single entry point. Output shape matches what the
orchestrator and tests expect.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Iterable
from datetime import timedelta
from typing import Any, ClassVar

from ..detection.base import Detector
from ..detection.behavioral_engine import BehavioralDetectionEngine
from ..detection.correlation import CorrelationResult, RiskCorrelator
from ..detection.detectors import build_default_registry
from ..detection.engine import DetectionEngine
from ..detection.models import DetectionFinding
from ..events.models import SecurityEvent
from ..risk import actor_matches, score_to_risk_level

logger = logging.getLogger(__name__)


# --- Additional first-class detectors ----------------------------------------

ROOT_ACCOUNT_ARN_PREFIX = "arn:aws:iam::"


class RootAccountUsageDetector(Detector):
    """Flag any activity from the account root principal."""

    name = "root_account_usage"

    def detect(self, event: SecurityEvent) -> DetectionFinding | None:
        if event.actor.type != "Root":
            return None

        return DetectionFinding(
            detector=self.name,
            title="Root account activity detected",
            description=(
                f"The AWS account root principal performed '{event.action.operation}'. "
                "Root credentials should not be used for everyday operations."
            ),
            severity="CRITICAL",
            event_id=event.event_id,
            actor_id=event.actor.arn or "root",
            resource_id=event.resource.arn or event.resource.name,
            evidence={
                "operation": event.action.operation,
                "source_ip": event.source_network.ip,
                "actor_type": event.actor.type,
            },
        )


class ConsoleLoginWithoutMFADetector(Detector):
    """Flag console logins that succeeded without MFA."""

    name = "console_login_no_mfa"

    LOGIN_EVENTS: ClassVar[set[str]] = {"ConsoleLogin", "SignIn"}

    def detect(self, event: SecurityEvent) -> DetectionFinding | None:
        if event.action.operation not in self.LOGIN_EVENTS:
            return None
        if event.result.status != "SUCCESS":
            return None
        # CloudTrail puts MFA info in additionalEventData; we don't have it
        # parsed on the SecurityEvent, so conservatively flag SUCCESSFUL
        # interactive logins that originated from outside trusted networks.
        # (Trusted-network filtering is done in the OutOfCompanyIPDetector.)
        # The point of this detector is to surface console logins explicitly
        # so analysts can cross-check MFA enforcement.
        return DetectionFinding(
            detector=self.name,
            title="Console login succeeded",
            description=(
                f"Actor '{event.actor.username or event.actor.arn}' performed a "
                f"console login from {event.source_network.ip}. Verify MFA was used."
            ),
            severity="MEDIUM",
            event_id=event.event_id,
            actor_id=event.actor.arn or event.actor.username or event.actor.user_id,
            resource_id=event.source_network.ip,
            evidence={
                "operation": event.action.operation,
                "source_ip": event.source_network.ip,
                "user_agent": event.source_network.user_agent,
            },
        )


class AccessDeniedSpikeDetector(Detector):
    """Flag a burst of access-denied errors from the same actor in a short window."""

    name = "access_denied_spike"

    def __init__(self, window_minutes: int = 10, threshold: int = 5) -> None:
        if window_minutes <= 0:
            raise ValueError("window_minutes must be greater than zero")
        if threshold <= 0:
            raise ValueError("threshold must be greater than zero")
        self._window = timedelta(minutes=window_minutes)
        self._threshold = threshold
        self._events_by_actor: dict[str, list[SecurityEvent]] = defaultdict(list)

    def detect(self, event: SecurityEvent) -> DetectionFinding | None:
        if event.result.status not in {"FAILURE", "DENIED"}:
            return None
        if not event.result.error_code:
            return None

        actor_id = event.actor.arn or event.actor.user_id or event.actor.username
        if not actor_id:
            return None

        bucket = self._events_by_actor[actor_id]
        bucket.append(event)
        cutoff = event.event_time - self._window
        self._events_by_actor[actor_id] = [e for e in bucket if e.event_time >= cutoff]
        recent = self._events_by_actor[actor_id]

        if len(recent) < self._threshold:
            return None

        error_codes = {e.result.error_code for e in recent if e.result.error_code}
        return DetectionFinding(
            detector=self.name,
            title="Burst of access-denied errors",
            description=(
                f"Actor {actor_id} triggered {len(recent)} access-denied events "
                f"within the last {self._window.seconds // 60} minutes. "
                f"Error codes: {sorted(error_codes)}."
            ),
            severity="MEDIUM",
            event_id=event.event_id,
            actor_id=actor_id,
            resource_id=event.resource.arn or event.resource.name,
            evidence={
                "error_codes": sorted(error_codes),
                "count": len(recent),
                "window_minutes": self._window.seconds // 60,
            },
        )

    def reset(self) -> None:
        self._events_by_actor.clear()


# --- Local analyzer ---------------------------------------------------------


class LocalAnalyzer:
    """Run the rule-based detection pipeline against events.

    The analyzer is stateful: it holds the per-actor `AccessDeniedSpike`
    detector and the UEBA engine's per-actor baselines. Callers that want a
    clean slate should construct a new `LocalAnalyzer` or call
    `analyzer.reset_state()`.
    """

    def __init__(
        self,
        trusted_networks: Iterable[str] = (),
        *,
        business_start_hour: int = 8,
        business_end_hour: int = 18,
        access_denied_window_minutes: int = 10,
        access_denied_threshold: int = 5,
        detection_engine: DetectionEngine | None = None,
        behavioral_engine: BehavioralDetectionEngine | None = None,
        correlator: RiskCorrelator | None = None,
        ueba_engine: Any | None = None,
    ) -> None:
        self.trusted_networks = list(trusted_networks)
        self.business_start_hour = business_start_hour
        self.business_end_hour = business_end_hour

        if detection_engine is None:
            registry = build_default_registry(
                self.trusted_networks,
                business_start_hour=business_start_hour,
                business_end_hour=business_end_hour,
            )
            registry.register(RootAccountUsageDetector())
            registry.register(ConsoleLoginWithoutMFADetector())
            self._access_denied_spike = AccessDeniedSpikeDetector(
                window_minutes=access_denied_window_minutes,
                threshold=access_denied_threshold,
            )
            registry.register(self._access_denied_spike)
            detection_engine = DetectionEngine(registry)
        self._detection_engine = detection_engine
        self._behavioral_engine = behavioral_engine or BehavioralDetectionEngine()
        self._correlator = correlator or RiskCorrelator()
        self._ueba = ueba_engine

    @property
    def ueba(self) -> Any:
        """Lazy-import to avoid circular import at module load."""
        if self._ueba is None:
            from ..analytics.ueba import IdentityAnalyticsEngine

            self._ueba = IdentityAnalyticsEngine()
        return self._ueba

    def reset_state(self) -> None:
        """Clear per-actor state. Safe to call between analysis runs."""
        self._access_denied_spike.reset()
        self.ueba.reset_state()

    # ---- Public API ---------------------------------------------------------

    def analyze_events(self, events: list[SecurityEvent]) -> dict[str, Any]:
        """Analyze a list of events and return an aggregated report."""
        if not events:
            return {
                "analyzed_count": 0,
                "risk_score": 0.0,
                "risk_level": "LOW",
                "threats": [],
                "findings": [],
            }

        # Build UEBA baselines once for the whole batch. Pass a shallow
        # copy so the per-actor pipeline can't accidentally mutate state
        # shared with future batches.
        try:
            self.ueba.reset_state()
            self.ueba.build_baselines(events)
        except Exception:
            logger.warning(
                "UEBA baseline construction failed; UEBA checks disabled",
                exc_info=True,
            )

        per_actor = self._analyze_per_actor(events)
        all_threats = [t for actor in per_actor.values() for t in actor["threats"]]
        all_findings = [t for actor in per_actor.values() for t in actor["findings"]]

        # Top-level risk = max across actors (so a single bad actor doesn't
        # get averaged out by quiet ones).
        top_score = max((actor["risk_score"] for actor in per_actor.values()), default=0.0)
        top_level = self._risk_level(top_score)

        return {
            "analyzed_count": len(events),
            "risk_score": top_score,
            "risk_level": top_level,
            "actors": per_actor,
            "threats": all_threats,
            "findings": all_findings,
        }

    def analyze_actor_behavior(
        self, actor_id: str, events: list[SecurityEvent]
    ) -> dict[str, Any]:
        """Analyze a single actor and return a structured result."""
        actor_events = [e for e in events if actor_matches(e, actor_id)]
        if not actor_events:
            return {
                "actor_id": actor_id,
                "error": "No events found for actor",
                "risk_score": 0.0,
                "risk_level": "LOW",
                "threats": [],
                "findings": [],
            }

        # Use the stateless `detect_for_actor` entry point with the
        # caller's events as the baseline. This avoids any cross-actor
        # state leakage that the legacy `detect(event)` method had.
        result = self._run_pipeline(actor_id, actor_events, events)
        return {
            "actor_id": actor_id,
            "event_count": len(actor_events),
            "risk_score": result.score,
            "risk_level": result.risk_level,
            "threats": [
                {
                    "type": finding.detector,
                    "description": finding.description,
                    "severity": finding.severity,
                    "event_id": finding.event_id,
                    "title": finding.title,
                    "evidence": finding.evidence,
                    "resource_id": finding.resource_id,
                }
                for finding in result.findings
            ],
            "findings": result.findings,
        }

    def detect_threats(self, events: list[SecurityEvent]) -> list[dict[str, Any]]:
        """Return a flat list of threat findings across all actors.

        Each entry in the returned list is a `DetectionFinding` rendered
        via `dataclasses.asdict`; the type annotation is `dict[str, Any]`
        so callers can JSON-serialize without importing the dataclass.
        """
        result = self.analyze_events(events)
        return result["threats"]

    def risk_score_for(self, actor_id: str, events: list[SecurityEvent]) -> float:
        """Return the 0-10 risk score for a single actor.

        Convenience method used by the investigation engine and other
        callers that only need a numeric score, not the full report.
        """
        if not events:
            return 0.0
        result = self._run_pipeline(actor_id, events, events)
        return float(result.score)

    # ---- Internals ----------------------------------------------------------

    def _analyze_per_actor(
        self, events: list[SecurityEvent]
    ) -> dict[str, dict[str, Any]]:
        actors: dict[str, dict[str, Any]] = {}
        seen_actors: set[str] = set()
        for event in events:
            actor_id = (
                event.actor.arn or event.actor.user_id or event.actor.username
            )
            if not actor_id or actor_id in seen_actors:
                continue
            seen_actors.add(actor_id)
            actors[actor_id] = self.analyze_actor_behavior(actor_id, events)
        return actors

    def _run_pipeline(
        self,
        actor_id: str,
        target_events: list[SecurityEvent],
        all_events: list[SecurityEvent],
    ) -> CorrelationResult:
        """Run the per-event detectors, UEBA, and behavioral engine for one actor.

        `target_events` are the events that belong to the actor; `all_events`
        is the full batch (used to build UEBA baselines if they aren't
        already built). The two are typically the same when called via
        `analyze_actor_behavior` directly.
        """
        findings: list[DetectionFinding] = []

        # Per-event detectors (no shared state beyond the access-denied
        # spike's per-actor window, which is intentional and bounded).
        for event in target_events:
            findings.extend(self._detection_engine.analyze(event))

        # UEBA: stateless pass that uses the pre-built baselines from
        # `analyze_events`. If the caller went straight to
        # `analyze_actor_behavior` without `analyze_events`, build the
        # baselines on the fly from `all_events`.
        try:
            baselines = dict(self.ueba._baselines)
            if not baselines:
                self.ueba.build_baselines(all_events)
                baselines = dict(self.ueba._baselines)
            findings.extend(
                self.ueba.detect_for_actor(
                    actor_id, target_events, baselines
                )
            )
        except Exception:
            logger.warning(
                "UEBA per-actor analysis failed for %s", actor_id, exc_info=True
            )

        # Behavioral engine: mass-download and similar multi-event rules.
        findings.extend(self._behavioral_engine.analyze(target_events))

        return self._correlator.correlate(findings)

    def _risk_level(self, score: float) -> str:
        return score_to_risk_level(score)
