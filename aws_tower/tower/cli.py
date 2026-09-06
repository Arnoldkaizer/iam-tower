"""AWS IAM Security Tower CLI.

Local rule-based security operations: ingestion, analysis, posture
assessment, and remediation. No external AI service is required.
"""

from __future__ import annotations

import enum
import random
import time
from typing import Any

import typer

from ..alerting import AlertManager, ConsoleAlertSink, JsonFileAlertSink, SnsAlertSink
from . import config as tower_config
from . import theme
from .orchestrator import SecurityTower

tower_app = typer.Typer(
    name="tower",
    help="AWS IAM Security Tower - local rule-based monitoring and threat analysis",
    no_args_is_help=True,
)

# Subcommand app for `aws-tower config ...`
config_app = typer.Typer(
    name="config",
    help="View or update persistent CLI configuration (trusted networks, business hours, ...).",
)
tower_app.add_typer(config_app)

_tower_instance: SecurityTower | None = None

# Used to print the banner exactly once per process. Suppressed when
# the user sets `AWS_TOWER_NO_BANNER=1` (handled inside the theme
# module).
_banner_shown = False


def show_banner() -> None:
    """Retained for command compatibility; the banner belongs to root help only.

    The installed entry point prints the banner before `aws-tower --help`.
    Subcommands must remain clean for scripting and machine-readable output.
    """
    return


def _maybe_no_color(no_color: bool) -> None:
    """Apply `--no-color` at the start of a command."""
    if no_color:
        theme.set_color(False)


class IncidentType(str, enum.Enum):
    """Valid values for the `remediate --type` flag."""

    COMPROMISED_CREDENTIAL = "compromised_credential"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    S3_PUBLIC_ACCESS = "s3_public_access"
    EXCESSIVE_PERMISSIONS = "excessive_permissions"
    UNAUTHORIZED_ACTIVITY = "unauthorized_activity"


def get_tower(
    trusted_networks: list[str] | None = None,
    business_start_hour: int | None = None,
    business_end_hour: int | None = None,
    access_denied_window_minutes: int | None = None,
    access_denied_threshold: int | None = None,
    min_risk_score: float | None = None,
) -> SecurityTower:
    """Get or create the default Security Tower orchestrator instance.

    Values default to whatever is in the persistent config file, falling
    back to module defaults if no config exists. Passing any of these
    explicitly overrides the persisted value for this run only.
    """
    global _tower_instance
    if _tower_instance is None:
        cfg = tower_config.load_config()
        _tower_instance = SecurityTower(
            trusted_networks=trusted_networks if trusted_networks is not None else cfg["trusted_networks"],
            business_start_hour=(
                business_start_hour
                if business_start_hour is not None
                else int(cfg["business_start_hour"])
            ),
            business_end_hour=(
                business_end_hour
                if business_end_hour is not None
                else int(cfg["business_end_hour"])
            ),
            repository_path=tower_config.database_path(),
        )
        window = access_denied_window_minutes
        if window is None:
            window = int(cfg["access_denied_window_minutes"])
        threshold = access_denied_threshold
        if threshold is None:
            threshold = int(cfg["access_denied_threshold"])
        _tower_instance.analyzer = _replace_access_denied_detector(
            _tower_instance.analyzer, window=window, threshold=threshold
        )
        configured_min_risk = min_risk_score
        if configured_min_risk is None:
            configured_min_risk = float(cfg["min_risk_score"])
        _tower_instance.alert_manager._min_risk_score = configured_min_risk
    return _tower_instance


def _replace_access_denied_detector(analyzer: Any, *, window: int, threshold: int) -> Any:
    """Rebuild the analyzer's AccessDeniedSpikeDetector with new thresholds.

    The detector is constructed once inside `LocalAnalyzer.__init__`, so
    to change `window_minutes` or `threshold` after construction we have
    to build a new analyzer and reuse its other components. This keeps
    the rest of the pipeline (UEBA, behavioral engine, correlator)
    untouched.
    """
    from ..analyzer.local_analyzer import (
        AccessDeniedSpikeDetector,
        LocalAnalyzer,
    )

    if isinstance(window, int) and window <= 0:
        raise ValueError("access_denied_window_minutes must be > 0")
    if isinstance(threshold, int) and threshold <= 0:
        raise ValueError("access_denied_threshold must be > 0")

    new_spike = AccessDeniedSpikeDetector(window_minutes=window, threshold=threshold)
    # Re-register the new spike in the existing registry so the detection
    # engine sees it on the next event. Replacing `analyzer.analyzer`
    # would also work but loses the other registry entries; this is
    # cheaper.
    try:
        registry = analyzer._detection_engine.registry  # type: ignore[attr-defined]
        registry._detectors = [  # type: ignore[attr-defined]
            detector
            for detector in registry.detectors()
            if not isinstance(detector, AccessDeniedSpikeDetector)
        ]
        registry.register(new_spike)
        analyzer._access_denied_spike = new_spike  # type: ignore[attr-defined]
    except AttributeError:
        # Fall back to rebuilding the whole analyzer if the layout differs.
        analyzer = LocalAnalyzer(
            trusted_networks=analyzer.trusted_networks,
            business_start_hour=analyzer.business_start_hour,
            business_end_hour=analyzer.business_end_hour,
            access_denied_window_minutes=window,
            access_denied_threshold=threshold,
        )
    return analyzer


@tower_app.command("ingest")
def ingest_logs(
    file_path: str | None = typer.Option(
        None, "--file", "-f", help="Optional local CloudTrail JSON/Gzip file override"
    ),
    s3_bucket: str | None = typer.Option(
        None, "--s3-bucket", "-b", help="Optional explicit S3 bucket override"
    ),
    s3_prefix: str = typer.Option(
        "", "--s3-prefix", "-p", help="S3 object key prefix"
    ),
    live: bool = typer.Option(
        True, "--live/--no-live", help="Ingest live CloudTrail API events (default: True)"
    ),
    auto_discover: bool = typer.Option(
        True, "--auto-discover/--no-auto-discover", help="Auto-discover S3 CloudTrail log buckets (default: True)"
    ),
    min_risk: float | None = typer.Option(
        None, "--min-risk", help="Minimum risk score threshold for alerting"
    ),
):
    """Fetch CloudTrail logs from S3/API and ingest into the local analyzer."""
    show_banner()
    tower = get_tower(min_risk_score=min_risk)

    events_count = 0

    if file_path:
        theme._console.print(
            f"[dim]Ingesting CloudTrail logs from specified file:[/dim] [bold]{file_path}[/bold]"
        )
        events = tower.ingest_file(file_path)
        events_count += len(events)
    else:
        theme._console.print(
            "[dim]Fetching CloudTrail telemetry (S3 Trail Auto-Discovery + Live API Feed)...[/dim]"
        )
        events, _ = tower.run_monitoring_cycle(
            use_live_cloudtrail=live,
            s3_bucket=s3_bucket,
            s3_prefix=s3_prefix,
            auto_discover=auto_discover,
        )
        events_count += len(events)

    theme._console.print(
        f"[ok]✓[/ok] Ingested [bold]{events_count}[/bold] security events."
    )


@tower_app.command("analyze")
def analyze_events(
    file_path: str | None = typer.Option(
        None, "--file", "-f", help="Optional local CloudTrail file override"
    ),
    s3_bucket: str | None = typer.Option(
        None, "--s3-bucket", "-b", help="Optional explicit S3 bucket override"
    ),
    live: bool = typer.Option(
        True, "--live/--no-live", help="Fetch live CloudTrail API events (default: True)"
    ),
    auto_discover: bool = typer.Option(
        True, "--auto-discover/--no-auto-discover", help="Auto-discover CloudTrail log buckets (default: True)"
    ),
    trusted_network: list[str] | None = typer.Option(
        None,
        "--trusted-network",
        "-n",
        help=(
            "CIDR or single IP considered in-company for IP-anomaly "
            "detection. May be passed multiple times. Overrides the "
            "persistent config for this run."
        ),
    ),
    business_start_hour: int | None = typer.Option(
        None, "--business-start-hour", help="Override business-hours start (0-23, UTC)."
    ),
    business_end_hour: int | None = typer.Option(
        None, "--business-end-hour", help="Override business-hours end (0-23, UTC)."
    ),
):
    """Fetch AWS logs and run the local rule-based threat analysis."""
    show_banner()
    validated = _parse_trusted_networks_arg(trusted_network or [])
    tower = get_tower(
        trusted_networks=validated,
        business_start_hour=business_start_hour,
        business_end_hour=business_end_hour,
    )
    events = []

    if file_path:
        theme._console.print(
            f"[dim]Reading events from file:[/dim] [bold]{file_path}[/bold]"
        )
        events = tower.ingest_file(file_path)
    else:
        theme._console.print(
            "[dim]Pulling logs from AWS CloudTrail S3 & API feeds...[/dim]"
        )
        events, _ = tower.run_monitoring_cycle(
            use_live_cloudtrail=live,
            s3_bucket=s3_bucket,
            auto_discover=auto_discover,
        )

    if not events:
        theme._console.print("[dim]No new events retrieved from AWS telemetry sources.[/dim]")
        return

    theme._console.print(
        f"Analyzing [bold]{len(events)}[/bold] security events with the local engine..."
    )
    analysis = tower.analyze_events(events)
    actors = analysis.get("actors", {}) or {}
    risk_score = float(analysis.get("risk_score", 0.0))
    risk_level = str(analysis.get("risk_level", "LOW"))
    theme.rule("Local analysis")
    theme.print_risk_gauge(risk_score, risk_level, label="Overall risk")
    if actors:
        theme._console.print()
        for actor_id, result in actors.items():
            theme.print_actor_summary(actor_id, result)
    findings = analysis.get("findings", []) or analysis.get("threats", [])
    if findings:
        theme._console.print()
        theme.print_findings_table(findings, title="All findings")
    else:
        theme._console.print("[dim]No findings to report.[/dim]")


@tower_app.command("posture")
def posture_analysis():
    """Evaluate AWS IAM policies, S3 bucket policies, and access keys with local rules."""
    show_banner()
    tower = get_tower()
    theme._console.print(
        "[dim]Gathering IAM policies, S3 bucket policies, and access keys via boto3...[/dim]"
    )
    theme._console.print("[dim]Analyzing AWS security posture with local rules...[/dim]")
    results = tower.assess_posture()
    theme.rule("Security posture")
    theme.print_posture(results)
    summary = results.get("summary", "")
    if summary:
        theme._console.print()
        theme._console.print(f"[dim]{summary}[/dim]")


@tower_app.command("remediate")
def remediate_actor(
    actor: str = typer.Option(
        ..., "--actor", "-a", help="Actor username, ARN, or principal ID to remediate"
    ),
    incident_type: IncidentType = typer.Option(
        IncidentType.UNAUTHORIZED_ACTIVITY,
        "--type",
        "-t",
        case_sensitive=False,
        help="Incident type: compromised_credential, privilege_escalation, s3_public_access, excessive_permissions, unauthorized_activity",
    ),
    execute: bool = typer.Option(
        False, "--execute", "-e", help="Execute generated remediation actions automatically"
    ),
):
    """Generate and (optionally) execute a remediation plan for an actor."""
    show_banner()
    tower = get_tower()
    incident_value = incident_type.value
    theme._console.print(
        f"Generating remediation plan for actor [bold]{actor}[/bold] "
        f"(type: [brand]{incident_value}[/brand])..."
    )

    plan = tower.generate_remediation_plan(
        incident_type=incident_value,
        details={"actor": actor, "reason": "Compromised or anomalous actor activity"},
    )

    theme.rule("Generated remediation plan")
    theme.print_remediation_plan(plan)

    if execute:
        theme._console.print()
        theme._console.print("[bold]Executing remediation actions...[/bold]")
        execution_res = tower.execute_remediation(plan)
        theme._console.print()
        theme.print_execution_results(execution_res.get("results", []))
        theme._console.print(
            f"[dim]Status:[/dim] "
            f"[bold]{execution_res.get('status', 'UNKNOWN')}[/bold]"
        )


@tower_app.command("monitor")
def monitor_loop(
    interval: int = typer.Option(
        60, "--interval", "-i", help="Polling interval in seconds"
    ),
    live: bool = typer.Option(
        True, "--live/--no-live", help="Poll live CloudTrail lookup events (default: True)"
    ),
    s3_bucket: str | None = typer.Option(
        None, "--s3-bucket", help="Poll CloudTrail logs from explicit S3 bucket"
    ),
    s3_prefix: str = typer.Option("", "--s3-prefix", help="S3 log prefix"),
    auto_discover: bool = typer.Option(
        True, "--auto-discover/--no-auto-discover", help="Auto-discover S3 CloudTrail log buckets (default: True)"
    ),
    json_log: str | None = typer.Option(
        None, "--json-log", help="Path to output JSON alert file"
    ),
    sns_topic: str | None = typer.Option(
        None, "--sns-topic", help="AWS SNS Topic ARN for high-risk alert dispatch"
    ),
    min_risk: float | None = typer.Option(
        None, "--min-risk", help="Minimum risk score threshold for alerts"
    ),
    max_cycles: int | None = typer.Option(
        None, "--max-cycles", help="Maximum monitoring cycles before stopping (default: unlimited)"
    ),
    trusted_network: list[str] | None = typer.Option(
        None,
        "--trusted-network",
        "-n",
        help="CIDR or single IP considered in-company. May be passed multiple times.",
    ),
    business_start_hour: int | None = typer.Option(
        None, "--business-start-hour", help="Override business-hours start (0-23, UTC)."
    ),
    business_end_hour: int | None = typer.Option(
        None, "--business-end-hour", help="Override business-hours end (0-23, UTC)."
    ),
    access_denied_window: int | None = typer.Option(
        None, "--access-denied-window", help="Access-denied spike window in minutes."
    ),
    access_denied_threshold: int | None = typer.Option(
        None, "--access-denied-threshold", help="Access-denied spike threshold."
    ),
):
    """Run continuous local security monitoring daemon."""
    show_banner()
    validated = _parse_trusted_networks_arg(trusted_network or [])
    tower = get_tower(
        trusted_networks=validated,
        business_start_hour=business_start_hour,
        business_end_hour=business_end_hour,
        access_denied_window_minutes=access_denied_window,
        access_denied_threshold=access_denied_threshold,
        min_risk_score=min_risk,
    )

    alert_manager = AlertManager(
        sinks=[ConsoleAlertSink()],
        min_risk_score=(
            min_risk
            if min_risk is not None
            else float(tower_config.load_config()["min_risk_score"])
        ),
    )
    if json_log:
        alert_manager.add_sink(JsonFileAlertSink(json_log))
    if sns_topic:
        alert_manager.add_sink(SnsAlertSink(sns_topic))

    tower.alert_manager = alert_manager

    theme.rule("Continuous monitoring")
    theme._console.print(
        f"   Polling interval: [bold]{interval}s[/bold] | "
        f"Live CloudTrail Feed: [bold]{'on' if live else 'off'}[/bold] | "
        f"S3 Auto-Discovery: [bold]{'on' if auto_discover else 'off'}[/bold]"
    )
    theme._console.print(
        f"   Trusted networks: "
        f"{', '.join(tower.analyzer.trusted_networks) if tower.analyzer.trusted_networks else '(none)'}"
    )
    theme._console.print(
        f"   Business hours: {tower.analyzer.business_start_hour}:00 - "
        f"{tower.analyzer.business_end_hour}:00 UTC"
    )
    theme._console.print(
        "   A small random jitter (0-10% of the interval) is added between cycles"
    )
    theme._console.print(
        "   to avoid synchronizing multiple instances against the AWS APIs."
    )
    theme._console.print("   Press [bold]Ctrl+C[/bold] to stop monitoring.\n")

    # Header for the live status panel.
    from rich.text import Text as _Text

    status_text = _Text("Waiting for first cycle...", style=theme.SEVERITY_STYLES["DIM"])
    with theme.live_status(status_text) as live:
        cycle = 0
        try:
            while True:
                cycle += 1
                theme._console.print(f"\n[brand]─── Cycle #{cycle} ───[/brand]")
                events, assessments = tower.run_monitoring_cycle(
                    use_live_cloudtrail=live,
                    s3_bucket=s3_bucket,
                    s3_prefix=s3_prefix,
                    auto_discover=auto_discover,
                    dispatch_alerts=False,
                )

                high_risk = sum(
                    1 for a in assessments
                    if a.risk_level in {"HIGH", "CRITICAL"}
                )
                theme.print_cycle_status(
                    cycle=cycle,
                    events=len(events),
                    assessments=len(assessments),
                    high_risk=high_risk,
                )
                for assessment in assessments:
                    alert = alert_manager.process_assessment(assessment)
                    if alert is None:
                        continue
                    theme.print_alert(alert)

                # Refresh the live status panel with the latest cycle info.
                next_text = _Text()
                next_text.append(
                    f"Last cycle: #{cycle}  events={len(events)}  "
                    f"assessments={len(assessments)}  high-risk={high_risk}",
                    style=theme.SEVERITY_STYLES["BRAND"],
                )
                live.update(next_text)

                if max_cycles and cycle >= max_cycles:
                    theme._console.print("Reached maximum specified cycles. Stopping monitor.")
                    break

                # Anti-thundering-herd jitter. Up to 10% of the interval,
                # capped at 10s, so very large intervals don't get excessive
                # additional waits.
                jitter = random.uniform(0, min(10.0, interval * 0.1))
                time.sleep(interval + jitter)
        except KeyboardInterrupt:
            theme._console.print("\n[dim]Security Tower monitoring stopped by user.[/dim]")


@tower_app.command("status")
def tower_status():
    """Display Security Tower operational status and risk metrics."""
    show_banner()
    tower = get_tower()

    all_events = tower.event_repo.query_by_time_range()
    all_assessments = tower.assessment_repo.list_latest(limit=100)
    high_risk_assessments = [a for a in all_assessments if a.risk_level in {"HIGH", "CRITICAL"}]

    theme.print_status_summary(
        total_events=len(all_events),
        total_actors=len(all_assessments),
        high_risk_actors=len(high_risk_assessments),
    )


@tower_app.command("incidents")
def list_incidents(
    min_risk: float = typer.Option(
        4.0, "--min-risk", "-r", help="Minimum risk score filter"
    ),
    limit: int = typer.Option(
        10, "--limit", "-n", help="Maximum incidents to display"
    ),
):
    """List recent security incidents and risk assessments."""
    show_banner()
    tower = get_tower()

    assessments = tower.assessment_repo.list_latest(limit=limit * 2)
    filtered = [a for a in assessments if a.risk_score >= min_risk]

    if not filtered:
        theme._console.print(
            f"\n[dim]No incidents at or above risk score {min_risk}.[/dim]"
        )
        return

    theme.rule(f"Security incidents (min risk ≥ {min_risk})")
    for assessment in filtered[:limit]:
        theme.print_actor_summary(
            assessment.actor_id,
            {
                "actor_id": assessment.actor_id,
                "risk_score": assessment.risk_score,
                "risk_level": assessment.risk_level,
                "event_count": 0,  # We don't have per-actor event count on the assessment alone
                "findings": [
                    {
                        "severity": f.severity,
                        "detector": getattr(f, "detector", ""),
                        "title": f.title,
                    }
                    for f in assessment.findings
                ],
            },
        )


@tower_app.command("investigate")
def investigate_target(
    actor: str | None = typer.Option(
        None, "--actor", "-a", help="Actor username, ARN, or principal ID"
    ),
    ip: str | None = typer.Option(
        None, "--ip", "-i", help="Source IP address to investigate"
    ),
):
    """Investigate security telemetry and timeline for an actor or IP address."""
    show_banner()
    tower = get_tower()

    if actor:
        theme.rule(f"Investigating actor: {actor}")
        profile = tower.investigation.get_actor_profile(actor)
        profile["actor_id"] = profile.get("actor_id", actor)
        theme.print_investigation_actor(profile)
        timeline = tower.investigation.query_timeline(actor_id=actor)
        if timeline:
            theme._console.print()
            theme.print_timeline(timeline)
        return

    if ip:
        theme.rule(f"Investigating IP: {ip}")
        profile = tower.investigation.get_ip_profile(ip)
        profile["ip"] = profile.get("ip", ip)
        theme.print_investigation_ip(profile)
        timeline = tower.investigation.query_timeline(ip_address=ip)
        if timeline:
            theme._console.print()
            theme.print_timeline(timeline)
        return

    theme._console.print(
        "[medium]Please specify --actor or --ip to investigate.[/medium]"
    )
    raise typer.Exit(code=1)


# --- Config subcommands -----------------------------------------------------


def _parse_networks(values: list[str]) -> list[str]:
    """Validate that each entry is parseable as a CIDR or single IP."""
    from ipaddress import ip_address, ip_network

    out: list[str] = []
    for raw in values:
        v = raw.strip()
        if not v:
            continue
        try:
            if "/" in v:
                ip_network(v, strict=False)
            else:
                ip_address(v)
        except ValueError as exc:
            raise typer.BadParameter(
                f"Invalid network or IP '{raw}': {exc}"
            ) from exc
        out.append(v)
    return out


@config_app.command("show")
def config_show():
    """Print the active persistent configuration."""
    show_banner()
    cfg = tower_config.load_config()
    theme.print_config(
        cfg,
        config_file=str(tower_config.config_path()),
    )


@config_app.command("set")
def config_set(
    trusted_networks: list[str] | None = typer.Option(
        None,
        "--trusted-network",
        "-n",
        help=(
            "CIDR or single IP considered 'in-company' for IP-anomaly "
            "detection. May be passed multiple times. Replaces the "
            "existing list when given; use --add-trusted-network to "
            "append instead."
        ),
    ),
    add_trusted_networks: list[str] | None = typer.Option(
        None,
        "--add-trusted-network",
        help="CIDR or single IP to append to the trusted-networks list.",
    ),
    clear_trusted_networks: bool = typer.Option(
        False,
        "--clear-trusted-networks",
        help="Empty the trusted-networks list.",
    ),
    business_start_hour: int | None = typer.Option(
        None,
        "--business-start-hour",
        help="Hour (0-23, UTC) when business hours start.",
    ),
    business_end_hour: int | None = typer.Option(
        None,
        "--business-end-hour",
        help="Hour (0-23, UTC) when business hours end.",
    ),
    access_denied_window: int | None = typer.Option(
        None,
        "--access-denied-window",
        help="Rolling window in minutes for the access-denied spike detector.",
    ),
    access_denied_threshold: int | None = typer.Option(
        None,
        "--access-denied-threshold",
        help="Number of access-denied events in the window that triggers a finding.",
    ),
    min_risk_score: float | None = typer.Option(
        None,
        "--min-risk-score",
        help="Alert dispatch threshold (0-10).",
    ),
):
    """Update the persistent CLI configuration.

    Examples
    --------

    Set two trusted networks and tighten the business hours window:

        aws-tower config set \\
            --trusted-network 10.0.0.0/8 \\
            --trusted-network 203.0.113.5 \\
            --business-start-hour 7 \\
            --business-end-hour 19

    Append a single network without replacing the existing list:

        aws-tower config set --add-trusted-network 192.168.0.0/16
    """
    show_banner()
    updates: dict[str, object] = {}

    if trusted_networks is not None:
        updates["trusted_networks"] = _parse_networks(trusted_networks)
    elif add_trusted_networks:
        existing = tower_config.load_config()["trusted_networks"]
        merged = list(existing) + _parse_networks(add_trusted_networks)
        # Dedupe while preserving order.
        seen: set[str] = set()
        updates["trusted_networks"] = [
            n for n in merged if not (n in seen or seen.add(n))  # type: ignore[func-returns-value]
        ]
    if clear_trusted_networks:
        updates["trusted_networks"] = []

    if business_start_hour is not None:
        if not 0 <= business_start_hour <= 23:
            raise typer.BadParameter("business_start_hour must be 0-23")
        updates["business_start_hour"] = business_start_hour
    if business_end_hour is not None:
        if not 0 <= business_end_hour <= 23:
            raise typer.BadParameter("business_end_hour must be 0-23")
        updates["business_end_hour"] = business_end_hour
    if (
        business_start_hour is not None
        and business_end_hour is not None
        and business_start_hour == business_end_hour
    ):
        raise typer.BadParameter("business_start_hour and business_end_hour cannot be equal")
    if access_denied_window is not None:
        if access_denied_window <= 0:
            raise typer.BadParameter("access_denied_window must be > 0")
        updates["access_denied_window_minutes"] = access_denied_window
    if access_denied_threshold is not None:
        if access_denied_threshold <= 0:
            raise typer.BadParameter("access_denied_threshold must be > 0")
        updates["access_denied_threshold"] = access_denied_threshold
    if min_risk_score is not None:
        if not 0.0 <= min_risk_score <= 10.0:
            raise typer.BadParameter("min_risk_score must be 0-10")
        updates["min_risk_score"] = min_risk_score

    if not updates:
        theme._console.print(
            "[medium]No changes specified. Use --help to see options.[/medium]"
        )
        raise typer.Exit(code=1)

    path = tower_config.save_config(updates)
    theme._console.print(
        f"[ok]✓[/ok] Wrote [bold]{len(updates)}[/bold] setting(s) to {path}"
    )
    config_show()


@config_app.command("reset")
def config_reset(
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the confirmation prompt"),
):
    """Reset all CLI configuration to defaults."""
    show_banner()
    if not yes:
        typer.confirm("Reset all configuration to defaults?", abort=True)
    if tower_config.config_path().exists():
        tower_config.config_path().unlink()
    theme._console.print("[ok]✓[/ok] Configuration reset to defaults.")
    config_show()


def _parse_trusted_networks_arg(values: list[str]) -> list[str]:
    """Parse --trusted-network flags from a command into validated CIDRs/IPs.

    Empty list means 'no override; use whatever is in the config'.
    """
    return _parse_networks(values)
