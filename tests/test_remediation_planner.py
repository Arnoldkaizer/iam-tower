"""Tests for the local remediation planner."""

import unittest

from aws_tower.remediation.planner import LocalRemediationPlanner


class TestLocalRemediationPlanner(unittest.TestCase):
    def setUp(self):
        self.planner = LocalRemediationPlanner()

    def test_compromised_credential_template(self):
        plan = self.planner.generate_plan(
            "compromised_credential",
            {"actor": "alice", "key_id": "AKIAEXAMPLE", "ip": "203.0.113.5"},
        )
        self.assertEqual(plan["incident_type"], "compromised_credential")
        actions = [step["action"] for step in plan["steps"]]
        self.assertIn("deactivate_key", actions)
        self.assertIn("block_ip", actions)
        # Parameters should have the actor filled in.
        deactivate_step = next(s for s in plan["steps"] if s["action"] == "deactivate_key")
        self.assertEqual(deactivate_step["parameters"]["user_name"], "alice")
        self.assertEqual(deactivate_step["parameters"]["access_key_id"], "AKIAEXAMPLE")

    def test_s3_public_access_template(self):
        plan = self.planner.generate_plan(
            "s3_public_access", {"bucket": "open-bucket"}
        )
        actions = [step["action"] for step in plan["steps"]]
        self.assertIn("update_bucket_policy", actions)
        self.assertIn("enable_public_access_block", actions)
        policy_step = next(s for s in plan["steps"] if s["action"] == "update_bucket_policy")
        self.assertEqual(policy_step["parameters"]["bucket_name"], "open-bucket")
        self.assertEqual(policy_step["parameters"]["effect"], "Deny")

    def test_unknown_incident_type_returns_error(self):
        plan = self.planner.generate_plan("something_we_dont_know", {"actor": "alice"})
        self.assertIn("error", plan)
        self.assertIn("Unknown incident type", plan["error"])

    def test_execute_plan_skips_confirmation_required_by_default(self):
        plan = self.planner.generate_plan(
            "compromised_credential",
            {"actor": "alice", "key_id": "AKIA", "ip": "1.2.3.4"},
        )
        actions = MagicMock()
        actions.execute.return_value = {"status": "SUCCESS"}
        result = self.planner.execute_plan(plan, actions)
        statuses = [r["status"] for r in result["results"]]
        # deactivate_key requires confirmation, so it should be SKIPPED.
        # block_ip does not, so it should be SUCCESS.
        self.assertIn("SKIPPED", statuses)
        self.assertIn("SUCCESS", statuses)
        # Only one of the two steps should have called the action executor.
        self.assertEqual(actions.execute.call_count, 1)

    def test_execute_plan_runs_when_force(self):
        plan = self.planner.generate_plan(
            "compromised_credential",
            {"actor": "alice", "key_id": "AKIA", "ip": "1.2.3.4"},
        )
        plan["force"] = True
        actions = MagicMock()
        actions.execute.return_value = {"status": "DEACTIVATED"}
        result = self.planner.execute_plan(plan, actions)
        self.assertEqual(result["status"], "COMPLETED")
        self.assertGreaterEqual(actions.execute.call_count, 1)


# Helper: the test module needs a MagicMock import.
from unittest.mock import MagicMock  # noqa: E402

if __name__ == "__main__":
    unittest.main()
