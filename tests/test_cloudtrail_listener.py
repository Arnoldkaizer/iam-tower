"""Tests for the local CloudTrail listener manager and ingestion."""

import gzip
import io
import json
import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from aws_tower.tower.ingestion import (
    CloudTrailListenerManager,
    LocalIngestion,
)
from aws_tower.tower.orchestrator import SecurityTower


class TestCloudTrailListeners(unittest.TestCase):
    """Test suite for CloudTrail S3 and API listeners."""

    def setUp(self):
        self.sample_record = {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": "AIDAEXAMPLE",
                "arn": "arn:aws:iam::123456789012:user/alice",
                "accountId": "123456789012",
                "userName": "alice",
            },
            "eventTime": "2026-08-30T12:00:00Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "AttachUserPolicy",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "198.51.100.42",
            "userAgent": "aws-cli/2.0",
            "requestParameters": {
                "userName": "bob",
                "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
            },
            "responseElements": None,
            "eventID": "evt-12345-67890",
            "eventType": "AwsApiCall",
        }

    def test_s3_listener_fetch_new_events_gzip(self):
        mock_s3 = MagicMock()
        mock_session = MagicMock()
        mock_session.client.return_value = mock_s3

        mock_paginator = MagicMock()
        mock_s3.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {
                "Contents": [
                    {"Key": "AWSLogs/123/CloudTrail/us-east-1/2026/08/30/log1.json.gz"},
                ]
            }
        ]

        json_data = json.dumps({"Records": [self.sample_record]}).encode("utf-8")
        out = io.BytesIO()
        with gzip.GzipFile(fileobj=out, mode="wb") as gz:
            gz.write(json_data)
        out.seek(0)
        mock_s3.get_object.return_value = {"Body": out}

        # The S3 listener was renamed into a private helper on the listener
        # manager, so use LocalIngestion directly.
        ingestion = LocalIngestion(boto3_session=mock_session)
        events = ingestion.ingest_s3(bucket_name="my-trail-bucket")

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].event_id, "evt-12345-67890")
        self.assertEqual(events[0].actor.username, "alice")
        self.assertEqual(events[0].action.operation, "AttachUserPolicy")

    def test_ingestion_accepts_null_request_parameters(self):
        record = {**self.sample_record, "requestParameters": None}

        events = LocalIngestion().ingest_records([record])

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].resource.type, "IAMUser")
        self.assertIsNone(events[0].resource.arn)

    def test_cloudtrail_api_listener_fetch_new_events(self):
        mock_ct = MagicMock()
        mock_session = MagicMock()
        mock_session.client.return_value = mock_ct

        mock_ct.lookup_events.return_value = {
            "Events": [
                {
                    "EventId": "evt-api-9999",
                    "EventTime": datetime.now(timezone.utc),
                    "EventName": "AttachUserPolicy",
                    "CloudTrailEvent": json.dumps(self.sample_record),
                }
            ]
        }

        ingestion = LocalIngestion(boto3_session=mock_session)
        events = ingestion.ingest_live_lookup()

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].event_id, "evt-12345-67890")
        self.assertEqual(events[0].actor.username, "alice")

    def test_auto_discovery(self):
        mock_ct = MagicMock()
        mock_session = MagicMock()
        mock_session.client.return_value = mock_ct
        mock_ct.describe_trails.return_value = {
            "trailList": [
                {"S3BucketName": "auto-discovered-bucket", "S3KeyPrefix": "logs/"}
            ]
        }

        manager = CloudTrailListenerManager(boto3_session=mock_session)
        discovered = manager.discover_cloudtrail_buckets()
        self.assertEqual(discovered, [("auto-discovered-bucket", "logs/")])

    def test_listener_manager_poll_all(self):
        mock_session = MagicMock()
        manager = CloudTrailListenerManager(boto3_session=mock_session)

        with (
            patch.object(manager.ingestion, "ingest_s3", return_value=[MagicMock()]) as mock_s3_fetch,
            patch.object(manager.ingestion, "ingest_live_lookup", return_value=[MagicMock()]) as mock_api_fetch,
        ):
            events = manager.poll_all(s3_bucket="test-bucket", use_live_api=True)
            self.assertEqual(len(events), 2)
            mock_s3_fetch.assert_called_once_with(
                bucket_name="test-bucket", prefix="", max_files=50
            )
            mock_api_fetch.assert_called_once_with(max_results=50)

    def test_orchestrator_integration(self):
        tower = SecurityTower()
        tower.analyzer = MagicMock()
        tower.analyzer.analyze_actor_behavior.return_value = {
            "risk_score": 2.0,
            "risk_level": "LOW",
            "threats": [],
            "findings": [],
        }
        # Pre-create a stub listener manager and inject it.
        stub_manager = MagicMock()
        stub_manager.poll_all.return_value = []
        tower._listener_manager = stub_manager
        events, assessments = tower.run_monitoring_cycle(
            s3_bucket="my-bucket", use_live_cloudtrail=True
        )
        self.assertEqual(events, [])
        self.assertEqual(assessments, [])
        stub_manager.poll_all.assert_called_once_with(
            s3_bucket="my-bucket",
            s3_prefix="",
            use_live_api=True,
            auto_discover=False,
        )


if __name__ == "__main__":
    unittest.main()
