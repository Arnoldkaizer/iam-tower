"""Visual theme for the Security Tower CLI.

All CLI output is routed through this module so the user gets a
consistent look: a banner at startup, color-coded severity
(red CRITICAL, orange HIGH, yellow MEDIUM, green LOW), gauges for
risk scores, tables for findings, and a live status panel during
`monitor`.

The module auto-detects whether stdout is a terminal. When it isn't
(piping to a file, CI, log capture), it falls back to plain text
without ANSI codes so machine-readable workflows keep working.
Tests can force one mode or the other with `set_color(False)` and
`set_color(True)`.

Rich is already a transitive dependency through Typer; importing
`rich` here is safe.
"""

from __future__ import annotations

import contextlib
import os
import sys
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from typing import Any

from rich.align import Align
from rich.console import Console, Group
from rich.live import Live
from rich.padding import Padding
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    TextColumn,
)
from rich.style import Style
from rich.table import Table
from rich.text import Text
from rich.theme import Theme


def _force_utf8_stdout() -> None:
    """Reconfigure stdout to UTF-8 so the banner's box-drawing characters
    render on Windows terminals (which default to cp1252).

    Python 3.7+ exposes ``sys.stdout.reconfigure``; on older versions or
    streams that don't support reconfigure we silently skip. Tests using
    StringIO streams are unaffected because they don't go through this
    path.
    """
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream is None:
            continue
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        with contextlib.suppress(Exception):
            reconfigure(encoding="utf-8", errors="replace")


# Apply once at import time. Cheap; idempotent.
_force_utf8_stdout()

# Severity styles — picked to read on both light and dark backgrounds.
SEVERITY_STYLES = {
    "CRITICAL": Style(color="red", bold=True),
    "HIGH": Style(color="orange3", bold=True),
    "MEDIUM": Style(color="yellow"),
    "LOW": Style(color="green"),
    "INFO": Style(color="cyan"),
    "OK": Style(color="green"),
    "DIM": Style(color="grey50"),
    "BRAND": Style(color="cyan", bold=True),
    "BRAND_DIM": Style(color="dodger_blue2"),
    "BANNER": Style(color="cyan", bold=True),
}

# Rich theme applied to every console this module owns.
_RICH_THEME = Theme(
    {
        "critical": SEVERITY_STYLES["CRITICAL"],
        "high": SEVERITY_STYLES["HIGH"],
        "medium": SEVERITY_STYLES["MEDIUM"],
        "low": SEVERITY_STYLES["LOW"],
        "info": SEVERITY_STYLES["INFO"],
        "ok": SEVERITY_STYLES["OK"],
        "dim": SEVERITY_STYLES["DIM"],
        "brand": SEVERITY_STYLES["BRAND"],
        "brand_dim": SEVERITY_STYLES["BRAND_DIM"],
        "banner": SEVERITY_STYLES["BANNER"],
    }
)


# --- Console singleton -------------------------------------------------------

def _detect_color() -> bool:
    """Whether to emit ANSI color codes by default.

    Honored by:
    - `NO_COLOR` env var (any non-empty value disables)
    - `FORCE_COLOR` env var (any non-empty value forces on)
    - Whether stdout is a TTY
    - `sys.stdout.isatty()` is the fallback
    """
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    try:
        return sys.stdout.isatty()
    except (AttributeError, ValueError):
        return False


# We hold a single Console instance so all output goes through the
# same width and color settings. Tests can replace it with
# `set_console_for_test`.
try:
    _console: Console = Console(
        theme=_RICH_THEME,
        soft_wrap=False,
        no_color=not _detect_color(),
        highlight=False,
        force_terminal=_detect_color(),
        width=Console().width or 120,
    )
except Exception:
    _console = Console(
        theme=_RICH_THEME,
        soft_wrap=False,
        no_color=not _detect_color(),
        highlight=False,
        force_terminal=_detect_color(),
        width=120,
    )


def get_console() -> Console:
    """Return the module-level Console instance."""
    return _console


def set_console_for_test(console: Console) -> None:
    """Replace the module-level Console. Intended for tests."""
    global _console
    _console = console


def set_color(enabled: bool) -> None:
    """Toggle color output at runtime.

    Replaces the current Console with one that has color on or off.
    Used by the `--no-color` CLI flag.
    """
    global _console
    _console = Console(
        theme=_RICH_THEME,
        soft_wrap=False,
        no_color=not enabled,
        highlight=False,
        force_terminal=enabled,
    )


# --- Banner ------------------------------------------------------------------

_BANNER_LINES: list[str] = [
    "██╗ █████╗ ███╗   ███╗    ████████╗ ██████╗ ██╗    ██╗███████╗██████╗",
    "██║██╔══██╗████╗ ████║    ╚══██╔══╝██╔═══██╗██║    ██║██╔════╝██╔══██╗",
    "██║███████║██╔████╔██║       ██║   ██║   ██║██║ █╗ ██║█████╗  ██████╔╝",
    "██║██╔══██║██║╚██╔╝██║       ██║   ██║   ██║██║███╗██║██╔══╝  ██╔══██╗",
    "██║██║  ██║██║ ╚═╝ ██║       ██║   ╚██████╔╝╚███╔███╔╝███████╗██║  ██║",
    "╚═╝╚═╝  ╚═╝╚═╝     ╚═╝       ╚═╝    ╚═════╝  ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝",
]


def _tagline() -> Text:
    return Text(
        "  AWS Identity Monitoring  ·  Local  ·  Rule-Based",
        style=SEVERITY_STYLES["BRAND_DIM"],
    )


def print_banner(tagline: bool = True) -> None:
    """Print the IAM TOWER wordmark.

    Suppressed if `AWS_TOWER_NO_BANNER=1` is set so scripts and CI can
    keep stdout clean.
    """
    if os.environ.get("AWS_TOWER_NO_BANNER"):
        return

    for line in _BANNER_LINES:
        _console.print(
            line,
            style=SEVERITY_STYLES["BANNER"],
            highlight=False,
        )

    if tagline:
        _console.print(_tagline())

    _console.print()

# --- Severity helpers --------------------------------------------------------


def severity_style(level: str) -> Style:
    """Return the Rich Style for a severity level.

    Unknown levels (e.g. "") get the dim style.
    """
    return SEVERITY_STYLES.get(level.upper(), SEVERITY_STYLES["DIM"])


def severity_badge(level: str) -> Text:
    """Render a severity label as a colored bracketed badge: [CRITICAL]."""
    style = severity_style(level)
    return Text(f" {level.upper()} ", style=style)


def print_severity(level: str, label: str = "") -> None:
    """Print a severity badge, optionally followed by a label."""
    badge = severity_badge(level)
    if label:
        _console.print(badge, " ", label)
    else:
        _console.print(badge)


# --- Risk gauge --------------------------------------------------------------


_GAUGE_WIDTH = 20  # characters in the bar


def _render_bar(score: float, width: int = _GAUGE_WIDTH) -> Text:
    """Render a horizontal gauge bar for a 0-10 score."""
    score = max(0.0, min(10.0, score))
    filled = round(score / 10.0 * width)
    empty = width - filled
    if score >= 8.0:
        style = SEVERITY_STYLES["CRITICAL"]
    elif score >= 6.0:
        style = SEVERITY_STYLES["HIGH"]
    elif score >= 3.0:
        style = SEVERITY_STYLES["MEDIUM"]
    else:
        style = SEVERITY_STYLES["LOW"]

    bar = Text()
    bar.append("█" * filled, style=style)
    bar.append("░" * empty, style=SEVERITY_STYLES["DIM"])
    return bar


def print_risk_gauge(score: float, level: str = "", label: str = "Overall risk") -> None:
    """Print `label  <bar>  score/10 LEVEL` on one line."""
    bar = _render_bar(score)
    text = Text()
    text.append(f"{label:<14}", style=SEVERITY_STYLES["DIM"])
    text.append("  ")
    text.append_text(bar)
    text.append("  ")
    text.append(f"{score:.1f}/10", style=Style(bold=True))
    if level:
        text.append("  ")
        text.append_text(severity_badge(level))
    _console.print(text)


# --- Tables ------------------------------------------------------------------


def _finding_row(finding: Any) -> tuple[str, str, str, str, str]:
    """Extract a row from a finding-like object or dict.

    Accepts either a `DetectionFinding` dataclass or a dict (the
    orchestrator sometimes serializes them).
    """
    if isinstance(finding, dict):
        return (
            str(finding.get("severity", "")),
            str(finding.get("detector") or finding.get("type") or ""),
            str(finding.get("title") or ""),
            str(finding.get("actor_id") or ""),
            str(finding.get("resource_id") or ""),
        )
    return (
        str(getattr(finding, "severity", "")),
        str(getattr(finding, "detector", "")),
        str(getattr(finding, "title", "")),
        str(getattr(finding, "actor_id", "") or ""),
        str(getattr(finding, "resource_id", "") or ""),
    )


def print_findings_table(findings: Sequence[Any], title: str = "Findings") -> None:
    """Print a colored findings table.

    Severity column is colored; everything else is plain text. A
    finding is anything that yields `(severity, detector, title, actor,
    resource)` via `_finding_row`.
    """
    if not findings:
        _console.print(Padding("[dim]No findings[/dim]", (0, 2)))
        return
    table = Table(
        title=title,
        show_lines=False,
        header_style="bold",
        expand=True,
        padding=(0, 1),
    )
    table.add_column("Severity", no_wrap=True, width=10)
    table.add_column("Detector", no_wrap=True, overflow="ellipsis")
    table.add_column("Title", min_width=22, ratio=3, overflow="fold")
    table.add_column("Actor", min_width=24, ratio=4, overflow="fold")
    table.add_column("Resource", min_width=16, ratio=3, overflow="fold")

    for finding in findings:
        severity, detector, title_text, actor, resource = _finding_row(finding)
        sev_text = Text(severity, style=severity_style(severity))
        table.add_row(sev_text, detector, title_text, actor, resource)
    _console.print(table)


# --- Actor summary panel -----------------------------------------------------


def print_actor_summary(actor_id: str, result: dict[str, Any]) -> None:
    """Print a panel summarizing a single actor's analysis result."""
    risk_score = float(result.get("risk_score", 0.0))
    risk_level = str(result.get("risk_level", "LOW"))
    event_count = int(result.get("event_count", 0))
    findings = result.get("findings", []) or result.get("threats", [])
    count = len(findings)

    body = Text()
    body.append("Actor   : ", style="dim")
    body.append(actor_id)
    body.append("\n")
    body.append("Events  : ", style="dim")
    body.append(str(event_count))
    body.append("    Findings: ", style="dim")
    body.append(str(count))
    body.append("\n\n")
    body.append_text(_render_bar(risk_score))
    body.append("  ")
    body.append(f"{risk_score:.1f}/10", style=Style(bold=True))
    body.append("  ")
    body.append_text(severity_badge(risk_level))
    body.append("\n\n")
    if findings:
        body.append("Top findings:\n", style="dim")
        for finding in findings[:3]:
            _, detector, title_text, _, _ = _finding_row(finding)
            severity = (
                finding.get("severity") if isinstance(finding, dict)
                else getattr(finding, "severity", "")
            )
            body.append_text(severity_badge(str(severity)))
            body.append(f"  {detector}: {title_text}\n")
    else:
        body.append("[dim]No findings[/dim]\n")

    border_style = severity_style(risk_level)
    _console.print(
        Panel(
            body,
            title=f"[bold]{actor_id}[/bold]",
            border_style=border_style,
            padding=(0, 2),
        )
    )


# --- Alert panel -------------------------------------------------------------


def print_alert(alert: dict[str, Any] | Any) -> None:
    """Print a high-contrast alert panel for a fired alert.

    Accepts an `Alert` dataclass or a dict.
    """
    if hasattr(alert, "to_dict"):
        payload = alert.to_dict()
    elif hasattr(alert, "__dict__") and not isinstance(alert, dict):
        payload = {
            "actor_id": getattr(alert, "actor_id", "unknown"),
            "risk_score": getattr(alert, "risk_score", 0.0),
            "risk_level": getattr(alert, "risk_level", "LOW"),
            "message": getattr(alert, "message", ""),
            "findings": getattr(alert, "findings", []),
        }
    else:
        payload = dict(alert)

    actor = str(payload.get("actor_id", "unknown"))
    score = float(payload.get("risk_score", 0.0))
    level = str(payload.get("risk_level", "LOW"))
    message = str(payload.get("message", ""))
    findings = payload.get("findings", []) or payload.get("threats", [])

    body = Text()
    body.append("Actor : ", style="dim")
    body.append(actor)
    body.append("\n")
    body.append("Score : ", style="dim")
    body.append_text(_render_bar(score))
    body.append("  ")
    body.append(f"{score:.1f}/10", style=Style(bold=True))
    body.append("  ")
    body.append_text(severity_badge(level))
    body.append("\n\n")
    if message:
        body.append(message)
        body.append("\n")
    if findings:
        body.append("\nFindings:\n", style="dim")
        for finding in findings[:5]:
            _, detector, title_text, _, _ = _finding_row(finding)
            severity = (
                finding.get("severity") if isinstance(finding, dict)
                else getattr(finding, "severity", "")
            )
            body.append_text(severity_badge(str(severity)))
            body.append(f"  {detector}: {title_text}\n")

    _console.print(
        Panel(
            body,
            title="[bold]SECURITY ALERT[/bold]",
            border_style=severity_style(level),
            padding=(0, 2),
        )
    )


# --- Posture table -----------------------------------------------------------


def print_posture(posture: dict[str, Any]) -> None:
    """Print posture results as four colored tables (one per section)."""
    overall = posture.get("overall_risk_score", {}) or {}
    overall_score = float(overall.get("score", 0.0))
    overall_level = str(overall.get("level", "LOW"))
    total_issues = int(overall.get("total_issues", 0))

    _console.print(
        Padding(
            Text.assemble(
                ("Posture overview\n", "bold"),
                ("Risk  ", "dim"),
                _render_bar(overall_score),
                f"  {overall_score:.1f}/10  ",
                severity_badge(overall_level),
                f"   ({total_issues} issues)",
            ),
            (0, 2),
        )
    )

    sections = [
        ("iam_analysis", "IAM Policies"),
        ("bucket_analysis", "S3 Buckets"),
        ("keys_analysis", "Access Keys"),
        ("users_analysis", "IAM Users"),
    ]
    for key, label in sections:
        section = posture.get(key) or {}
        issues = section.get("issues", []) or []
        level = str(section.get("risk_level", "LOW"))
        count = int(section.get("issue_count", 0))
        if not issues:
            _console.print(
                Padding(
                    Text.assemble(
                        (f"{label:<14} ", "bold"),
                        severity_badge(level),
                        f"  {count} issues",
                    ),
                    (0, 2),
                )
            )
            continue
        table = Table(
            title=f"{label} ({count} issues, {level})",
            title_style=severity_style(level),
            show_lines=False,
            header_style="bold",
        )
        table.add_column("Severity", no_wrap=True)
        table.add_column("Rule", no_wrap=True)
        table.add_column("Resource", no_wrap=True)
        table.add_column("Description")
        for issue in issues:
            sev = str(issue.get("severity", ""))
            rule = str(issue.get("rule", ""))
            resource = str(issue.get("resource", ""))
            description = str(issue.get("description", ""))
            table.add_row(
                Text(sev, style=severity_style(sev)),
                rule,
                resource,
                description,
            )
        _console.print(table)


# --- Config panel ------------------------------------------------------------


def print_config(
    cfg: dict[str, Any],
    config_file: str = "",
    title: str = "Active configuration",
) -> None:
    """Print the active configuration as a key/value panel."""
    body = Text()
    body.append("Config file              : ", style="dim")
    body.append(config_file or "(in-memory)")
    body.append("\n")
    body.append(
        "Trusted networks          : ", style="dim"
    )
    networks = cfg.get("trusted_networks") or []
    body.append(", ".join(networks) if networks else "[dim](none)[/dim]")
    body.append("\n")
    body.append("Business hours (UTC)     : ", style="dim")
    body.append(
        f"{int(cfg.get('business_start_hour', 8)):02d}:00 - "
        f"{int(cfg.get('business_end_hour', 18)):02d}:00"
    )
    body.append("\n")
    body.append("Access-denied window     : ", style="dim")
    body.append(f"{int(cfg.get('access_denied_window_minutes', 10))} min")
    body.append("\n")
    body.append("Access-denied threshold  : ", style="dim")
    body.append(f"{int(cfg.get('access_denied_threshold', 5))} events")
    body.append("\n")
    body.append("Alert min risk score     : ", style="dim")
    body.append(f"{float(cfg.get('min_risk_score', 4.0))}")
    _console.print(
        Panel(
            body,
            title=f"[bold]{title}[/bold]",
            border_style=SEVERITY_STYLES["BRAND"],
            padding=(0, 2),
        )
    )


# --- Investigation -----------------------------------------------------------


def print_investigation_actor(profile: dict[str, Any]) -> None:
    body = Text()
    body.append("Total events     : ", style="dim")
    body.append(str(profile.get("total_events", 0)))
    body.append("\n")
    body.append("Risk score       : ", style="dim")
    score = float(profile.get("risk_score", 0.0))
    body.append_text(_render_bar(score))
    body.append("  ")
    body.append(f"{score:.1f}/10 ", style=Style(bold=True))
    body.append_text(severity_badge(str(profile.get("risk_level", "LOW"))))
    body.append("\n")
    body.append("Unique IPs       : ", style="dim")
    body.append(", ".join(profile.get("unique_ips", [])) or "(none)")
    body.append("\n")
    body.append("Operations seen  : ", style="dim")
    body.append(
        ", ".join(profile.get("operations_summary", [])) or "(none)"
    )
    _console.print(
        Panel(
            body,
            title=f"[bold]Actor: {profile.get('actor_id', '?')}[/bold]",
            border_style=SEVERITY_STYLES["BRAND"],
            padding=(0, 2),
        )
    )


def print_investigation_ip(profile: dict[str, Any]) -> None:
    body = Text()
    body.append("Total events       : ", style="dim")
    body.append(str(profile.get("total_events", 0)))
    body.append("\n")
    body.append("Associated actors  : ", style="dim")
    body.append(", ".join(profile.get("associated_actors", [])) or "(none)")
    body.append("\n")
    body.append("Services accessed  : ", style="dim")
    body.append(", ".join(profile.get("services_accessed", [])) or "(none)")
    _console.print(
        Panel(
            body,
            title=f"[bold]IP: {profile.get('ip', '?')}[/bold]",
            border_style=SEVERITY_STYLES["BRAND"],
            padding=(0, 2),
        )
    )


def print_timeline(events: Sequence[Any], limit: int = 50) -> None:
    if not events:
        _console.print(Padding("[dim]No events[/dim]", (0, 2)))
        return
    table = Table(title="Timeline", show_lines=False, header_style="bold")
    table.add_column("Time", no_wrap=True)
    table.add_column("IP", no_wrap=True)
    table.add_column("Service", no_wrap=True)
    table.add_column("Operation")
    table.add_column("Result", no_wrap=True)
    for event in events[:limit]:
        time_str = event.event_time.strftime("%Y-%m-%d %H:%M:%S")
        ip = event.source_network.ip if event.source_network else "unknown"
        service = event.source.service if event.source else "unknown"
        op = event.action.operation if event.action else "?"
        status = event.result.status if event.result else "?"
        style = (
            SEVERITY_STYLES["CRITICAL"] if status == "FAILURE"
            else SEVERITY_STYLES["OK"] if status == "SUCCESS"
            else SEVERITY_STYLES["DIM"]
        )
        table.add_row(
            time_str,
            ip,
            service,
            op,
            Text(status, style=style),
        )
    _console.print(table)


# --- Remediation -------------------------------------------------------------


def print_remediation_plan(plan: dict[str, Any]) -> None:
    steps = plan.get("steps", [])
    summary = str(plan.get("summary", ""))
    if summary:
        _console.print(Padding(f"[bold]{summary}[/bold]", (0, 2)))
    if not steps:
        _console.print(Padding("[dim]No steps in plan[/dim]", (0, 2)))
        return
    table = Table(title="Remediation plan", header_style="bold")
    table.add_column("#", no_wrap=True)
    table.add_column("Action", no_wrap=True)
    table.add_column("Description")
    table.add_column("Parameters")
    table.add_column("Auto", no_wrap=True)
    table.add_column("Confirm", no_wrap=True)
    for idx, step in enumerate(steps, 1):
        action = str(step.get("action", ""))
        description = str(step.get("description", ""))
        params = step.get("parameters", {}) or {}
        params_text = (
            ", ".join(f"{k}={v}" for k, v in params.items())
            if params
            else "-"
        )
        auto = "yes" if step.get("auto_executable") else "no"
        confirm = "yes" if step.get("requires_confirmation") else "no"
        table.add_row(str(idx), action, description, params_text, auto, confirm)
    _console.print(table)


def print_execution_results(results: Sequence[dict[str, Any]]) -> None:
    if not results:
        _console.print(Padding("[dim]No results[/dim]", (0, 2)))
        return
    table = Table(title="Execution results", header_style="bold")
    table.add_column("Action", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Detail")
    for entry in results:
        action = str(entry.get("action", ""))
        status = str(entry.get("status", ""))
        detail = ""
        if status == "SUCCESS":
            result = entry.get("result") or {}
            detail = str(result.get("status", ""))
        elif status == "FAILED":
            detail = str(entry.get("error", ""))
        elif status == "SKIPPED":
            detail = str(entry.get("reason", ""))
        style = {
            "SUCCESS": SEVERITY_STYLES["OK"],
            "FAILED": SEVERITY_STYLES["CRITICAL"],
            "SKIPPED": SEVERITY_STYLES["DIM"],
            "PARTIAL": SEVERITY_STYLES["MEDIUM"],
            "COMPLETED": SEVERITY_STYLES["OK"],
        }.get(status, SEVERITY_STYLES["DIM"])
        table.add_row(action, Text(status, style=style), detail)
    _console.print(table)


# --- Status line (for monitor cycles) ---------------------------------------


def print_cycle_status(
    cycle: int,
    events: int,
    assessments: int,
    high_risk: int = 0,
    duration_s: float | None = None,
) -> None:
    """Print a one-line status for a monitor cycle."""
    text = Text()
    text.append(f"[Cycle #{cycle:>4}] ", style=SEVERITY_STYLES["BRAND"])
    text.append("events=", style="dim")
    text.append(str(events))
    text.append("  actors=", style="dim")
    text.append(str(assessments))
    text.append("  high-risk=", style="dim")
    text.append(str(high_risk), style=SEVERITY_STYLES["HIGH"] if high_risk else None)
    if duration_s is not None:
        text.append(f"  took={duration_s:.1f}s", style="dim")
    _console.print(text)


# --- Live status panel (for monitor) ----------------------------------------


@contextmanager
def live_status(initial: Text) -> Iterator[Live]:
    """Context manager that shows a refreshing status panel.

    On non-TTY output the panel degrades to a plain Text print: the
    status text is printed once and subsequent updates are printed
    inline.
    """
    if not _console.is_terminal:
        _console.print(initial)
        yield _NullLive(_console)
        return
    with Live(
        initial,
        console=_console,
        refresh_per_second=2,
        transient=False,
    ) as live:
        yield live


class _NullLive:
    """Stand-in for `Live` on non-TTY output.

    `update()` just prints; `stop()` is a no-op. Used when stdout is
    not a TTY so `monitor` keeps working in pipes and CI.
    """

    def __init__(self, console: Console) -> None:
        self._console = console

    def update(self, renderable: Any, refresh: bool = False) -> None:
        self._console.print(renderable)

    def stop(self) -> None:
        return None


# --- Small helpers used by multiple commands --------------------------------


def progress_bar(label: str, total: int | None = None) -> Progress:
    """Return a Progress instance styled for the theme."""
    return Progress(
        TextColumn(f"[bold]{label}[/bold]"),
        BarColumn(bar_width=30, style=SEVERITY_STYLES["BRAND"], complete_style=SEVERITY_STYLES["OK"]),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=_console,
        transient=True,
        total=total,
    )


def rule(title: str = "") -> None:
    """Print a horizontal rule with an optional centered title."""
    if title:
        _console.rule(f"[bold]{title}[/bold]")
    else:
        _console.rule()


def print_status_summary(
    total_events: int,
    total_actors: int,
    high_risk_actors: int,
) -> None:
    """Print a status summary panel used by `aws-tower status`."""
    body = Text()
    body.append("Total ingested events : ", style="dim")
    body.append(str(total_events))
    body.append("\n")
    body.append("Total assessed actors : ", style="dim")
    body.append(str(total_actors))
    body.append("\n")
    body.append("High-risk incidents   : ", style="dim")
    body.append(
        str(high_risk_actors),
        style=SEVERITY_STYLES["HIGH"] if high_risk_actors else None,
    )
    _console.print(
        Panel(
            body,
            title="[bold]Security Tower status[/bold]",
            border_style=SEVERITY_STYLES["BRAND"],
            padding=(0, 2),
        )
    )


def print_posture_summary(overall: dict[str, Any]) -> None:
    """Print a short posture summary used by `analyze` (when included)."""
    score = float(overall.get("score", 0.0))
    level = str(overall.get("level", "LOW"))
    text = Text()
    text.append("Posture risk  ", style="dim")
    text.append_text(_render_bar(score))
    text.append("  ")
    text.append(f"{score:.1f}/10", style=Style(bold=True))
    text.append("  ")
    text.append_text(severity_badge(level))
    _console.print(text)


# Public re-export of `Align` and `Group` so callers can build custom
# renderables without re-importing from `rich`.
__all__ = [
    "Align",
    "Group",
    "get_console",
    "live_status",
    "print_actor_summary",
    "print_alert",
    "print_banner",
    "print_config",
    "print_cycle_status",
    "print_execution_results",
    "print_findings_table",
    "print_investigation_actor",
    "print_investigation_ip",
    "print_posture",
    "print_posture_summary",
    "print_remediation_plan",
    "print_risk_gauge",
    "print_severity",
    "print_status_summary",
    "print_timeline",
    "progress_bar",
    "rule",
    "set_color",
    "set_console_for_test",
    "severity_badge",
    "severity_style",
]
