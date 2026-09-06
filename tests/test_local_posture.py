"""Tests for the local posture analyzer."""

import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from aws_tower.posture.local_posture import LocalPostureAnalyzer


def client_error(code: str) -> ClientError:
    return ClientError({"Error": {"Code": code}}, "op")


def make_iam_client(
    *,
    policies: list[dict] | None = None,
    users: list[dict] | None = None,
    password_policy: dict | None = None,
    account_summary: dict | None = None,
) -> MagicMock:
    iam = MagicMock()

    policies = policies or []
    users = users or []

    # Each get_paginator call returns a fresh MagicMock so list_policies and
    # list_users don't share a consumed iterator.
    def _paginator(name: str) -> MagicMock:
        p = MagicMock()
        if name == "list_policies":
            p.paginate.return_value = iter([{"Policies": policies}])
        elif name == "list_users":
            p.paginate.return_value = iter([{"Users": users}])
        else:
            p.paginate.return_value = iter([{}])
        return p

    iam.get_paginator.side_effect = _paginator

    # For list_access_keys (no paginator) - return empty per user.
    iam.list_access_keys.return_value = {"AccessKeyMetadata": []}
    # list_mfa_devices - empty by default.
    iam.list_mfa_devices.return_value = {"MFADevices": []}
    # get_user - return a default profile.
    iam.get_user.return_value = {"User": {}}

    if password_policy is not None:
        iam.get_account_password_policy.return_value = {"PasswordPolicy": password_policy}
    else:
        iam.get_account_password_policy.side_effect = client_error(
            "NoSuchEntity"
        )

    if account_summary is not None:
        iam.get_account_summary.return_value = {"SummaryMap": account_summary}
    else:
        iam.get_account_summary.return_value = {
            "SummaryMap": {"AccountMFAEnabled": True}
        }

    return iam


def make_s3_client(buckets: list[dict] | None = None) -> MagicMock:
    s3 = MagicMock()
    s3.list_buckets.return_value = {"Buckets": buckets or []}
    # Default: every get_* call raises a "not found" ClientError so the analyzer
    # correctly emits the "missing config" finding.
    not_found_policy = ClientError(
        {"Error": {"Code": "NoSuchBucketPolicy"}}, "get_bucket_policy"
    )
    s3.get_bucket_policy.side_effect = not_found_policy
    s3.get_bucket_encryption.side_effect = client_error(
        "ServerSideEncryptionConfigurationNotFoundError"
    )
    s3.get_public_access_block.side_effect = client_error(
        "NoSuchPublicAccessBlockConfiguration"
    )
    s3.get_bucket_versioning.side_effect = client_error("NoSuchVersioning")
    return s3


class TestLocalPostureAnalyzer(unittest.TestCase):
    def test_admin_wildcard_policy_is_critical(self):
        iam = make_iam_client(
            policies=[
                {
                    "Arn": "arn:aws:iam::1:policy/admin",
                    "PolicyName": "admin",
                }
            ]
        )
        iam.list_policy_versions.return_value = {
            "Versions": [{"VersionId": "v1", "IsDefaultVersion": True}]
        }
        iam.get_policy_version.return_value = {
            "PolicyVersion": {
                "Document": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {"Effect": "Allow", "Action": ["*"], "Resource": ["*"]}
                    ],
                }
            }
        }
        analyzer = LocalPostureAnalyzer(iam_client=iam, s3_client=make_s3_client())
        result = analyzer.analyze_posture()
        issues = result["iam_analysis"]["issues"]
        rules = {i["rule"] for i in issues}
        self.assertIn("iam_policy_admin_wildcard", rules)
        severities = {i["severity"] for i in issues if i["rule"] == "iam_policy_admin_wildcard"}
        self.assertIn("CRITICAL", severities)

    def test_bucket_missing_public_access_block(self):
        s3 = make_s3_client([{"Name": "no-pab-bucket"}])
        s3.get_public_access_block.side_effect = client_error(
            "NoSuchPublicAccessBlockConfiguration"
        )
        analyzer = LocalPostureAnalyzer(iam_client=make_iam_client(), s3_client=s3)
        result = analyzer.analyze_posture()
        rules = {i["rule"] for i in result["bucket_analysis"]["issues"]}
        self.assertIn("s3_public_access_block_missing", rules)

    def test_bucket_public_allow_statement(self):
        s3 = make_s3_client([{"Name": "open-bucket"}])
        # Clear default side_effects and replace with the values this test
        # wants. side_effect and return_value are mutually exclusive in
        # MagicMock, so we set side_effect = None first.
        s3.get_public_access_block.side_effect = None
        s3.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            }
        }
        s3.get_bucket_policy.side_effect = None
        s3.get_bucket_policy.return_value = {
            "Policy": '{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::open-bucket/*"}]}'
        }
        s3.get_bucket_encryption.side_effect = client_error(
            "ServerSideEncryptionConfigurationNotFoundError"
        )
        s3.get_bucket_versioning.side_effect = None
        s3.get_bucket_versioning.return_value = {"Status": "Suspended"}
        analyzer = LocalPostureAnalyzer(iam_client=make_iam_client(), s3_client=s3)
        result = analyzer.analyze_posture()
        rules = {i["rule"] for i in result["bucket_analysis"]["issues"]}
        self.assertIn("s3_policy_public_allow", rules)
        self.assertIn("s3_encryption_missing", rules)
        self.assertIn("s3_versioning_disabled", rules)

    def test_account_mfa_disabled(self):
        iam = make_iam_client(account_summary={"AccountMFAEnabled": False})
        analyzer = LocalPostureAnalyzer(iam_client=iam, s3_client=make_s3_client())
        result = analyzer.analyze_posture()
        rules = {i["rule"] for i in result["users_analysis"]["issues"]}
        self.assertIn("iam_account_mfa_disabled", rules)

    def test_user_no_mfa(self):
        iam = make_iam_client(
            users=[{"UserName": "bob"}],
            account_summary={"AccountMFAEnabled": True},
        )
        iam.get_login_profile.return_value = {
            "LoginProfile": {"CreateDate": datetime(2026, 8, 30, tzinfo=timezone.utc)}
        }
        analyzer = LocalPostureAnalyzer(iam_client=iam, s3_client=make_s3_client())
        result = analyzer.analyze_posture()
        rules = {i["rule"] for i in result["users_analysis"]["issues"]}
        self.assertIn("iam_user_no_mfa", rules)

    def test_password_policy_weak(self):
        iam = make_iam_client(
            password_policy={
                "MinimumPasswordLength": 8,
                "RequireSymbols": False,
                "PasswordReusePrevention": 0,
            }
        )
        analyzer = LocalPostureAnalyzer(iam_client=iam, s3_client=make_s3_client())
        result = analyzer.analyze_posture()
        rules = {i["rule"] for i in result["users_analysis"]["issues"]}
        self.assertIn("iam_password_policy_weak_length", rules)
        self.assertIn("iam_password_policy_no_symbols", rules)
        self.assertIn("iam_password_policy_no_reuse_prevention", rules)

    def test_overall_risk_aggregates(self):
        iam = make_iam_client(
            policies=[
                {"Arn": "arn:aws:iam::1:policy/admin", "PolicyName": "admin"}
            ]
        )
        iam.list_policy_versions.return_value = {
            "Versions": [{"VersionId": "v1", "IsDefaultVersion": True}]
        }
        iam.get_policy_version.return_value = {
            "PolicyVersion": {
                "Document": {
                    "Statement": [
                        {"Effect": "Allow", "Action": ["*"], "Resource": ["*"]}
                    ]
                }
            }
        }
        analyzer = LocalPostureAnalyzer(iam_client=iam, s3_client=make_s3_client())
        result = analyzer.analyze_posture()
        self.assertGreater(result["overall_risk_score"]["score"], 0.0)
        self.assertIn(
            result["overall_risk_score"]["level"], ("MEDIUM", "HIGH", "CRITICAL")
        )


if __name__ == "__main__":
    unittest.main()
