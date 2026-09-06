"""Tests for the local remediation action executor."""

import unittest
from unittest.mock import MagicMock

from aws_tower.remediation.actions import RemediationActions
from aws_tower.remediation.planner import LocalRemediationPlanner


class TestRenderStep(unittest.TestCase):
    """The plan template renderer must not corrupt literal `{` characters."""

    def test_filled_placeholders_are_replaced(self):
        rendered = LocalRemediationPlanner._render_step(
            {
                "action": "noop",
                "parameters": {"user_name": "{actor}", "access_key_id": "{key_id}"},
                "description": "",
                "auto_executable": False,
                "requires_confirmation": False,
            },
            {"actor": "alice", "key_id": "AKIAEXAMPLE"},
        )
        self.assertEqual(rendered["parameters"]["user_name"], "alice")
        self.assertEqual(rendered["parameters"]["access_key_id"], "AKIAEXAMPLE")

    def test_unfilled_placeholders_stay_as_token(self):
        # An unfilled {key_id} must not raise and must remain in the output
        # so the operator can see what's missing.
        rendered = LocalRemediationPlanner._render_step(
            {
                "action": "noop",
                "parameters": {"access_key_id": "{key_id}"},
                "description": "",
                "auto_executable": False,
                "requires_confirmation": False,
            },
            {},  # no details at all
        )
        self.assertEqual(rendered["parameters"]["access_key_id"], "{key_id}")

    def test_literal_braces_in_non_string_values_are_preserved(self):
        # Values that aren't strings are passed through untouched.
        rendered = LocalRemediationPlanner._render_step(
            {
                "action": "noop",
                "parameters": {"count": 5, "list": ["{a}", "literal"]},
                "description": "",
                "auto_executable": False,
                "requires_confirmation": False,
            },
            {},
        )
        self.assertEqual(rendered["parameters"]["count"], 5)
        self.assertEqual(rendered["parameters"]["list"], ["{a}", "literal"])

    def test_no_braces_in_string(self):
        rendered = LocalRemediationPlanner._render_step(
            {
                "action": "noop",
                "parameters": {"bucket_name": "open-bucket"},
                "description": "",
                "auto_executable": False,
                "requires_confirmation": False,
            },
            {},
        )
        self.assertEqual(rendered["parameters"]["bucket_name"], "open-bucket")


class TestUpdateBucketPolicySnapshot(unittest.TestCase):
    def test_prior_policy_is_snapshotted(self):
        actions = RemediationActions(boto3_session=MagicMock())
        prior = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::1:root"}, "Action": "s3:*", "Resource": "*"}
            ],
        }
        actions.s3_client.get_bucket_policy.return_value = {"Policy": '{"Version":"2012-10-17","Statement":[]}'}
        actions.s3_client.get_bucket_policy.side_effect = None
        import json as _json
        actions.s3_client.get_bucket_policy.return_value = {"Policy": _json.dumps(prior)}

        result = actions.update_bucket_policy({"bucket_name": "b", "effect": "Deny", "principal": "*"})
        self.assertEqual(result["status"], "UPDATED")
        self.assertTrue(result["had_existing_policy"])
        self.assertEqual(result["prior_policy"], prior)
        # The new statement is appended.
        self.assertIn("new_statement", result)
        # The s3 client was called to write the new policy.
        actions.s3_client.put_bucket_policy.assert_called_once()

    def test_no_prior_policy_yields_none_snapshot(self):
        actions = RemediationActions(boto3_session=MagicMock())
        from botocore.exceptions import ClientError

        actions.s3_client.get_bucket_policy.side_effect = ClientError(
            {"Error": {"Code": "NoSuchBucketPolicy"}}, "get_bucket_policy"
        )

        result = actions.update_bucket_policy({"bucket_name": "b", "effect": "Deny", "principal": "*"})
        self.assertEqual(result["status"], "UPDATED")
        self.assertFalse(result["had_existing_policy"])
        self.assertIsNone(result["prior_policy"])

    def test_missing_bucket_name_is_an_error(self):
        actions = RemediationActions(boto3_session=MagicMock())
        result = actions.update_bucket_policy({})
        self.assertIn("error", result)


if __name__ == "__main__":
    unittest.main()
