# ==============================================================================
# AWS IAM Security Tower - Infrastructure as Code (Terraform)
# Best-practice Terraform deployment for CloudTrail, S3, EventBridge, IAM & Alerting
# ==============================================================================

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "IAM Security Tower"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

data "aws_caller_identity" "current" {}

data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  network_azs = slice(data.aws_availability_zones.available.names, 0, 2)
}

# ==============================================================================
# 0. INSPECTION VPC NETWORK
# ==============================================================================

resource "aws_vpc" "inspection" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${var.name_prefix}-vpc"
  }
}

resource "aws_internet_gateway" "inspection" {
  vpc_id = aws_vpc.inspection.id

  tags = {
    Name = "${var.name_prefix}-igw"
  }
}

resource "aws_subnet" "firewall" {
  count = length(local.network_azs)

  vpc_id            = aws_vpc.inspection.id
  availability_zone = local.network_azs[count.index]
  cidr_block        = var.firewall_subnet_cidrs[count.index]

  tags = {
    Name = "${var.name_prefix}-firewall-${local.network_azs[count.index]}"
    Tier = "firewall"
  }
}

resource "aws_subnet" "protected" {
  count = length(local.network_azs)

  vpc_id            = aws_vpc.inspection.id
  availability_zone = local.network_azs[count.index]
  cidr_block        = var.protected_subnet_cidrs[count.index]

  tags = {
    Name = "${var.name_prefix}-protected-${local.network_azs[count.index]}"
    Tier = "protected"
  }
}

resource "aws_subnet" "public" {
  count = length(local.network_azs)

  vpc_id                  = aws_vpc.inspection.id
  availability_zone       = local.network_azs[count.index]
  cidr_block              = var.public_subnet_cidrs[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.name_prefix}-public-${local.network_azs[count.index]}"
    Tier = "public"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.inspection.id

  tags = {
    Name = "${var.name_prefix}-public-rt"
  }
}

resource "aws_route" "public_internet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.inspection.id
}

resource "aws_route_table_association" "public" {
  count = length(local.network_azs)

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_eip" "nat" {
  count  = length(local.network_azs)
  domain = "vpc"

  depends_on = [aws_internet_gateway.inspection]
}

resource "aws_nat_gateway" "public" {
  count = length(local.network_azs)

  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id

  depends_on = [aws_internet_gateway.inspection]

  tags = {
    Name = "${var.name_prefix}-nat-${local.network_azs[count.index]}"
  }
}

resource "aws_route_table" "firewall" {
  count  = length(local.network_azs)
  vpc_id = aws_vpc.inspection.id

  tags = {
    Name = "${var.name_prefix}-firewall-rt-${local.network_azs[count.index]}"
  }
}

resource "aws_route" "firewall_internet" {
  count = length(local.network_azs)

  route_table_id         = aws_route_table.firewall[count.index].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.public[count.index].id
}

resource "aws_route_table_association" "firewall" {
  count = length(local.network_azs)

  subnet_id      = aws_subnet.firewall[count.index].id
  route_table_id = aws_route_table.firewall[count.index].id
}

resource "aws_route_table" "protected" {
  count  = length(local.network_azs)
  vpc_id = aws_vpc.inspection.id

  tags = {
    Name = "${var.name_prefix}-protected-rt-${local.network_azs[count.index]}"
  }
}

resource "aws_route_table_association" "protected" {
  count = length(local.network_azs)

  subnet_id      = aws_subnet.protected[count.index].id
  route_table_id = aws_route_table.protected[count.index].id
}

module "network_firewall" {
  source = "./modules/network_firewall"

  name                 = "${var.name_prefix}-network-firewall"
  vpc_id               = aws_vpc.inspection.id
  firewall_subnet_ids  = toset(aws_subnet.firewall[*].id)
  allowed_source_cidrs = var.allowed_source_cidrs
  protected_cidrs      = [var.vpc_cidr]

  tags = {
    Name = "${var.name_prefix}-network-firewall"
  }
}

resource "aws_route" "protected_through_firewall" {
  count = length(local.network_azs)

  route_table_id         = aws_route_table.protected[count.index].id
  destination_cidr_block = "0.0.0.0/0"
  vpc_endpoint_id        = module.network_firewall.firewall_endpoint_ids[local.network_azs[count.index]]
}

resource "aws_route_table" "internet_gateway_edge" {
  vpc_id = aws_vpc.inspection.id

  tags = {
    Name = "${var.name_prefix}-igw-edge-rt"
  }
}

resource "aws_route_table_association" "internet_gateway_edge" {
  gateway_id     = aws_internet_gateway.inspection.id
  route_table_id = aws_route_table.internet_gateway_edge.id
}

resource "aws_route" "internet_to_protected" {
  count = length(local.network_azs)

  route_table_id         = aws_route_table.internet_gateway_edge.id
  destination_cidr_block = var.protected_subnet_cidrs[count.index]
  vpc_endpoint_id        = module.network_firewall.firewall_endpoint_ids[local.network_azs[count.index]]
}

# ==============================================================================
# 1. CLOUDTRAIL S3 LOG BUCKET (ENCRYPTED & PUBLIC ACCESS BLOCKED)
# ==============================================================================

resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket        = "iam-tower-cloudtrail-logs-${data.aws_caller_identity.current.account_id}"
  force_destroy = false
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_logs_encryption" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "block_public_access" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "cloudtrail_s3_policy" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.cloudtrail_logs.arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

# ==============================================================================
# 2. MULTI-REGION CLOUDTRAIL TRAIL
# ==============================================================================

resource "aws_cloudtrail" "main_trail" {
  name                          = "iam-tower-main-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_logging                = true

  depends_on = [aws_s3_bucket_policy.cloudtrail_s3_policy]
}

# ==============================================================================
# 3. REAL-TIME EVENTBRIDGE RULE FOR IMMEDIATE ALERTING
# ==============================================================================

resource "aws_cloudwatch_event_rule" "sensitive_security_events" {
  name        = "iam-tower-sensitive-api-rule"
  description = "Triggers immediate IAM Tower alerting on high-risk API calls (1-5s latency)"

  event_pattern = jsonencode({
    source        = ["aws.iam", "aws.s3", "aws.sts"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "AttachUserPolicy",
        "AttachRolePolicy",
        "PutUserPolicy",
        "PutRolePolicy",
        "CreateAccessKey",
        "CreateRole",
        "UpdateAssumeRolePolicy",
        "PutBucketPolicy",
        "DeleteBucketPolicy"
      ]
    }
  })
}

# ==============================================================================
# 4. IAM ROLE FOR IAM TOWER COMPUTE / DAEMON / LAMBDA
# ==============================================================================

resource "aws_iam_role" "iam_tower_role" {
  name = "iam-tower-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = ["lambda.amazonaws.com", "ecs-tasks.amazonaws.com", "ec2.amazonaws.com"]
        }
      }
    ]
  })
}

resource "aws_iam_policy" "iam_tower_policy" {
  name        = "iam-tower-service-policy"
  description = "Permissions for CloudTrail log retrieval, local rule-based analysis, and containment"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CloudTrailAndS3Read"
        Effect = "Allow"
        Action = [
          "cloudtrail:DescribeTrails",
          "cloudtrail:GetTrailStatus",
          "cloudtrail:LookupEvents",
          "iam:GetAccountPasswordPolicy",
          "iam:GetAccountSummary",
          "iam:GetLoginProfile",
          "iam:GetPolicyVersion",
          "iam:ListAccessKeys",
          "iam:ListMFADevices",
          "iam:ListPolicies",
          "iam:ListPolicyVersions",
          "iam:ListUsers",
          "s3:GetBucketEncryption",
          "s3:GetBucketPolicy",
          "s3:GetBucketVersioning",
          "s3:GetPublicAccessBlock",
          "s3:ListAllMyBuckets",
          "s3:ListBucket",
          "s3:GetObject"
        ]
        Resource = [
          aws_s3_bucket.cloudtrail_logs.arn,
          "${aws_s3_bucket.cloudtrail_logs.arn}/*",
          "*"
        ]
      },
      {
        Sid    = "AutomatedRemediation"
        Effect = "Allow"
        Action = [
          "iam:DetachUserPolicy",
          "iam:DetachRolePolicy",
          "iam:UpdateAccessKey",
          "iam:PutUserPolicy"
        ]
        Resource = "*"
      },
      {
        Sid    = "SNSAlerting"
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = aws_sns_topic.security_alerts.arn
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "iam_tower_attach" {
  role       = aws_iam_role.iam_tower_role.name
  policy_arn = aws_iam_policy.iam_tower_policy.arn
}

# ==============================================================================
# 5. SNS ALERT TOPIC & SUBSCRIPTIONS
# ==============================================================================

resource "aws_sns_topic" "security_alerts" {
  name = "iam-tower-security-alerts"
}

resource "aws_sns_topic_subscription" "email_alert" {
  count     = var.alert_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}
