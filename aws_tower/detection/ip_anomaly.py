"""Detector for activity from untrusted IP addresses."""

from __future__ import annotations

from collections.abc import Iterable
from ipaddress import ip_address, ip_network

from ..events.models import SecurityEvent
from .base import Detector
from .models import DetectionFinding


class OutOfCompanyIPDetector(Detector):
    """Detect activity originating outside trusted networks."""

    name = "out_of_company_ip"

    def __init__(
        self,
        trusted_networks: Iterable[str],
    ) -> None:
        self._trusted_networks = [
            ip_network(network)
            for network in trusted_networks
        ]

    def detect(
        self,
        event: SecurityEvent,
    ) -> DetectionFinding | None:

        source_ip = event.source_network.ip

        if not source_ip:
            return None

        try:
            address = ip_address(source_ip)
        except (TypeError, ValueError):
            return None

        is_trusted = any(
            address in network
            for network in self._trusted_networks
        )

        if is_trusted:
            return None

        return DetectionFinding(
            detector=self.name,
            title="Activity from untrusted IP",
            description=(
                "AWS activity originated from an IP "
                "outside the configured company networks."
            ),
            severity="HIGH",
            event_id=event.event_id,
            actor_id=(
                event.actor.arn
                or event.actor.user_id
                or event.actor.username
            ),
            resource_id=(
                event.resource.arn
                or event.resource.name
            ),
            evidence={
                "source_ip": source_ip,
                "trusted_networks": [
                    str(network)
                    for network in self._trusted_networks
                ],
                "operation": event.action.operation,
                "category": event.action.category,
            },
        )
