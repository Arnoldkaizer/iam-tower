"""Tests for the CLI theme module.

The tests use a captured Rich Console (writing to a StringIO) so we
can assert on actual rendered output. The theme is presentation
layer; we don't test visual layout, only that:
- nothing raises when called with reasonable inputs
- the rendered output contains the expected identifiers (level names,
  titles, parameter values)
- color/style attributes are applied to the severity column / gauge
"""

from __future__ import annotations

import io
import unittest
from dataclasses import dataclass

from rich.console import Console
from rich.text import Text

from aws_tower.tower import theme

# --- Fixtures ---------------------------------------------------------------


@dataclass
class _Finding:
    severity: str
    detector: str
    title: str
    actor_id: str = "alice"
    resource_id: str = "arn:aws:iam::1:user/alice"
    description: str = ""


def _make_console() -> tuple[Console, io.StringIO]:
    """Return a fresh (console, buffer) pair for capturing theme output."""
    buffer = io.StringIO()
    console = Console(
        file=buffer,
        force_terminal=False,
        no_color=True,
        width=120,
        soft_wrap=False,
    )
    return console, buffer


def setUpModule() -> None:
    # Replace the module-level console with a no-op capture so importing
    # the module doesn't write to the real stdout. Individual tests
    # override with their own console when they want to assert on output.
    _make_console()
    theme.set_color(False)


# --- Tests ------------------------------------------------------------------


class TestBanner(unittest.TestCase):
    def test_banner_renders_without_raising(self):
        console, buf = _make_console()
        theme.set_console_for_test(console)
        try:
            theme.print_banner(tagline=False)
        finally:
            theme.set_console_for_test(_make_console()[0])
        out = buf.getvalue()
        # The banner uses █ (U+2588). Just assert it didn't crash and
        # wrote something.
        self.assertTrue(len(out) > 0)

    def test_banner_can_be_suppressed(self):
        import os

        os.environ["AWS_TOWER_NO_BANNER"] = "1"
        try:
            console, buf = _make_console()
            theme.set_console_for_test(console)
            try:
                theme.print_banner()
            finally:
                theme.set_console_for_test(_make_console()[0])
            self.assertEqual(buf.getvalue(), "")
        finally:
            del os.environ["AWS_TOWER_NO_BANNER"]


class TestSeverity(unittest.TestCase):
    def test_severity_style_known_levels(self):
        # CRITICAL maps to a red+bold style; LOW maps to green; unknown
        # maps to DIM.
        self.assertEqual(theme.severity_style("CRITICAL").color.name, "red")
        self.assertTrue(theme.severity_style("CRITICAL").bold)
        self.assertEqual(theme.severity_style("LOW").color.name, "green")
        self.assertEqual(theme.severity_style(""), theme.SEVERITY_STYLES["DIM"])

    def test_severity_badge_includes_level(self):
        badge = theme.severity_badge("HIGH")
        self.assertIsInstance(badge, Text)
        self.assertIn("HIGH", badge.plain)


class TestRiskGauge(unittest.TestCase):
    def test_risk_gauge_includes_score_and_level(self):
        console, buf = _make_console()
        theme.set_console_for_test(console)
        try:
            theme.print_risk_gauge(8.1, "CRITICAL", label="Test")
        finally:
            theme.set_console_for_test(_make_console()[0])
        out = buf.getvalue()
        self.assertIn("8.1/10", out)
        self.assertIn("CRITICAL", out)
        self.assertIn("Test", out)

    def test_risk_gauge_without_level(self):
        console, buf = _make_console()
        theme.set_console_for_test(console)
        try:
            theme.print_risk_gauge(2.0, "")
        finally:
            theme.set_console_for_test(_make_console()[0])
        out = buf.getvalue()
        self.assertIn("2.0/10", out)


class TestFindingsTable(unittest.TestCase):
    def test_findings_table_with_finding_dataclass(self):
        console, buf = _make_console()
        theme.set_console_for_test(console)
        findings = [
            _Finding("CRITICAL", "root_account_usage", "Root activity"),
            _Finding("HIGH", "restricted_activity", "IAM mutation"),
        ]
        try:
            theme.print_findings_table(findings)
        finally:
            theme.set_console_for_test(_make_console()[0])
        out = buf.getvalue()
        self.assertIn("CRITICAL", out)
        self.assertIn("HIGH", out)
        self.assertIn("root_account_usage", out)
        self.assertIn("restricted_activity", out)

    def test_findings_table_with_dict_finding(self):
        console, buf = _make_console()
        theme.set_console_for_test(console)
        findings = [
            {
                "severity": "MEDIUM",
                "detector": "irregular_hour",
                "title": "After hours",
                "actor_id": "bob",
                "resource_id": "arn:...",
            }
        ]
        try:
            theme.print_findings_table(findings)
        finally:
            theme.set_console_for_test(_make_console()[0])
        out = buf.getvalue()
        self.assertIn("MEDIUM", out)
        self.assertIn("irregular_hour", out)

    def test_findings_table_empty(self):
        console, buf = _make_console()
        theme.set_console_for_test(console)
        try:
            theme.print_findings_table([])
        finally:
            theme.set_console_for_test(_make_console()[0])
        out = buf.getvalue()
        self.assertIn("No findings", out)


class TestActorSummary(unittest.TestCase):
    def test_actor_summary_includes_actor_and_score(self):
        console, buf = _make_console()
        theme.set_console_for_test(console)
        result = {
            "actor_id": "alice",
            "risk_score": 7.5,
            "risk_level": "HIGH",
            "event_count": 12,
            "findings": [
                _Finding("HIGH", "restricted_activity", "x"),
            ],
        }
        try:
            theme.print_actor_summary("alice", result)
        finally:
            theme.set_console_for_test(_make_console()[0])
        out = buf.getvalue()
        self.assertIn("alice", out)
        self.assertIn("7.5/10", out)
        self.assertIn("HIGH", out)
        self.assertIn("restricted_activity", out)


class TestAlert(unittest.TestCase):
    def test_alert_panel_renders_from_dict(self):
        console, buf = _make_console()
        theme.set_console_for_test(console)
        alert = {
            "actor_id": "bob",
            "risk_score": 9.0,
            "risk_level": "CRITICAL",
            "message": "Compromised credential",
            "findings": [
                _Finding("CRITICAL", "root_account_usage", "Root used"),
            ],
        }
        try:
            theme.print_alert(alert)
        finally:
            theme.set_console_for_test(_make_console()[0])
        out = buf.getvalue()
        self.assertIn("SECURITY ALERT", out)
        self.assertIn("bob", out)
        self.assertIn("9.0/10", out)
        self.assertIn("CRITICAL", out)


class TestPosture(unittest.TestCase):
    def test_posture_renders_all_sections(self):
        console, buf = _make_console()
        theme.set_console_for_test(console)
        posture = {
            "overall_risk_score": {"score": 6.5, "level": "HIGH", "total_issues": 3},
            "iam_analysis": {
                "risk_level": "HIGH",
                "issue_count": 1,
                "issues": [
                    {
                        "severity": "CRITICAL",
                        "rule": "iam_policy_admin_wildcard",
                        "resource": "arn:aws:iam::1:policy/admin",
                        "description": "admin policy allows *",
                    }
                ],
            },
            "bucket_analysis": {"risk_level": "LOW", "issue_count": 0, "issues": []},
            "keys_analysis": {"risk_level": "LOW", "issue_count": 0, "issues": []},
            "users_analysis": {"risk_level": "LOW", "issue_count": 0, "issues": []},
        }
        try:
            theme.print_posture(posture)
        finally:
            theme.set_console_for_test(_make_console()[0])
        out = buf.getvalue()
        self.assertIn("Posture overview", out)
        self.assertIn("IAM Policies", out)
        self.assertIn("S3 Buckets", out)
        self.assertIn("Access Keys", out)
        self.assertIn("IAM Users", out)
        self.assertIn("iam_policy_admin_wildcard", out)


class TestConfigPanel(unittest.TestCase):
    def test_config_panel_includes_all_fields(self):
        console, buf = _make_console()
        theme.set_console_for_test(console)
        cfg = {
            "trusted_networks": ["10.0.0.0/8", "192.168.0.0/16"],
            "business_start_hour": 8,
            "business_end_hour": 18,
            "access_denied_window_minutes": 10,
            "access_denied_threshold": 5,
            "min_risk_score": 4.0,
        }
        try:
            theme.print_config(cfg, config_file="~/.aws_tower.json")
        finally:
            theme.set_console_for_test(_make_console()[0])
        out = buf.getvalue()
        self.assertIn("10.0.0.0/8", out)
        self.assertIn("192.168.0.0/16", out)
        self.assertIn("08:00", out)
        self.assertIn("18:00", out)


class TestInvestigation(unittest.TestCase):
    def test_actor_panel(self):
        console, buf = _make_console()
        theme.set_console_for_test(console)
        profile = {
            "actor_id": "alice",
            "total_events": 42,
            "risk_score": 6.0,
            "risk_level": "HIGH",
            "unique_ips": ["1.2.3.4", "5.6.7.8"],
            "operations_summary": ["AttachUserPolicy", "CreateAccessKey"],
        }
        try:
            theme.print_investigation_actor(profile)
        finally:
            theme.set_console_for_test(_make_console()[0])
        out = buf.getvalue()
        self.assertIn("alice", out)
        self.assertIn("6.0/10", out)
        self.assertIn("HIGH", out)
        self.assertIn("1.2.3.4", out)
        self.assertIn("AttachUserPolicy", out)

    def test_ip_panel(self):
        console, buf = _make_console()
        theme.set_console_for_test(console)
        profile = {
            "ip": "1.2.3.4",
            "total_events": 7,
            "associated_actors": ["alice", "bob"],
            "services_accessed": ["iam.amazonaws.com", "s3.amazonaws.com"],
        }
        try:
            theme.print_investigation_ip(profile)
        finally:
            theme.set_console_for_test(_make_console()[0])
        out = buf.getvalue()
        self.assertIn("1.2.3.4", out)
        self.assertIn("alice", out)
        self.assertIn("iam.amazonaws.com", out)


class TestRemediation(unittest.TestCase):
    def test_plan_table(self):
        console, buf = _make_console()
        theme.set_console_for_test(console)
        plan = {
            "summary": "Compromised credential",
            "steps": [
                {
                    "action": "deactivate_key",
                    "description": "Deactivate access key",
                    "parameters": {"user_name": "alice", "access_key_id": "AKIA"},
                    "auto_executable": True,
                    "requires_confirmation": True,
                },
                {
                    "action": "block_ip",
                    "description": "Add IP to deny list",
                    "parameters": {"ip": "1.2.3.4"},
                    "auto_executable": False,
                    "requires_confirmation": False,
                },
            ],
        }
        try:
            theme.print_remediation_plan(plan)
        finally:
            theme.set_console_for_test(_make_console()[0])
        out = buf.getvalue()
        self.assertIn("Compromised credential", out)
        self.assertIn("deactivate_key", out)
        self.assertIn("block_ip", out)
        self.assertIn("user_name=alice", out)

    def test_execution_results_table(self):
        console, buf = _make_console()
        theme.set_console_for_test(console)
        results = [
            {"action": "deactivate_key", "status": "SUCCESS", "result": {"status": "DEACTIVATED"}},
            {"action": "block_ip", "status": "FAILED", "error": "permission denied"},
            {"action": "tag_user", "status": "SKIPPED", "reason": "requires confirmation"},
        ]
        try:
            theme.print_execution_results(results)
        finally:
            theme.set_console_for_test(_make_console()[0])
        out = buf.getvalue()
        self.assertIn("SUCCESS", out)
        self.assertIn("FAILED", out)
        self.assertIn("SKIPPED", out)
        self.assertIn("permission denied", out)


class TestStatusLine(unittest.TestCase):
    def test_cycle_status_contains_counts(self):
        console, buf = _make_console()
        theme.set_console_for_test(console)
        try:
            theme.print_cycle_status(42, 100, 5, high_risk=2, duration_s=1.2)
        finally:
            theme.set_console_for_test(_make_console()[0])
        out = buf.getvalue()
        self.assertIn("42", out)
        self.assertIn("100", out)
        self.assertIn("5", out)
        self.assertIn("1.2", out)

    def test_status_summary_panel(self):
        console, buf = _make_console()
        theme.set_console_for_test(console)
        try:
            theme.print_status_summary(100, 5, 1)
        finally:
            theme.set_console_for_test(_make_console()[0])
        out = buf.getvalue()
        self.assertIn("100", out)
        self.assertIn("5", out)
        self.assertIn("1", out)


class TestEncoding(unittest.TestCase):
    def test_force_utf8_does_not_break_stringio(self):
        # StringIO doesn't have reconfigure; the helper must skip it
        # without raising. Indirect: import the module, exercise a theme
        # function, confirm no crash.
        console, buf = _make_console()
        theme.set_console_for_test(console)
        try:
            theme.print_banner(tagline=False)
            theme.print_risk_gauge(5.0, "MEDIUM")
        finally:
            theme.set_console_for_test(_make_console()[0])
        # Both calls produced output without raising.
        self.assertGreater(len(buf.getvalue()), 0)


if __name__ == "__main__":
    unittest.main()
