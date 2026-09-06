"""AWS error handling utilities."""

from botocore.exceptions import ClientError


def get_aws_error_code(error: ClientError) -> str:
    """Extract the AWS error code from a Boto3 ClientError."""
    return error.response["Error"]["Code"]
