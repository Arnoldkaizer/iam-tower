output "cloudtrail_s3_bucket_name" {
  value       = aws_s3_bucket.cloudtrail_logs.id
  description = "The S3 bucket name created for CloudTrail log storage"
}

output "cloudtrail_arn" {
  value       = aws_cloudtrail.main_trail.arn
  description = "ARN of the main multi-region CloudTrail"
}

output "iam_tower_role_arn" {
  value       = aws_iam_role.iam_tower_role.arn
  description = "IAM Execution Role ARN for IAM Security Tower"
}

output "sns_topic_arn" {
  value       = aws_sns_topic.security_alerts.arn
  description = "SNS Topic ARN for dispatching security incident alerts"
}

output "inspection_vpc_id" {
  value       = aws_vpc.inspection.id
  description = "ID of the VPC containing the inspected network."
}

output "protected_subnet_ids" {
  value       = aws_subnet.protected[*].id
  description = "Protected subnet IDs that route through Network Firewall."
}

output "network_firewall_arn" {
  value       = module.network_firewall.firewall_arn
  description = "ARN of the Network Firewall protecting the VPC."
}

output "network_firewall_endpoint_ids" {
  value       = module.network_firewall.firewall_endpoint_ids
  description = "Network Firewall endpoint IDs by Availability Zone."
}
