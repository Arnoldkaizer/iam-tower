output "firewall_arn" {
  value       = aws_networkfirewall_firewall.this.arn
  description = "ARN of the Network Firewall."
}

output "firewall_endpoint_ids" {
  value = {
    for attachment in aws_networkfirewall_firewall.this.firewall_status[0].sync_states :
    attachment.availability_zone => attachment.attachment[0].endpoint_id
  }
  description = "Firewall endpoint IDs by Availability Zone for route-table configuration."
}

output "firewall_policy_arn" {
  value       = aws_networkfirewall_firewall_policy.this.arn
  description = "ARN of the firewall policy."
}

output "stateful_rule_group_arn" {
  value       = aws_networkfirewall_rule_group.out_of_range_sources.arn
  description = "ARN of the stateful out-of-range source rule group."
}
