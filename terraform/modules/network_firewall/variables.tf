variable "name" {
  type        = string
  description = "Name of the AWS Network Firewall."

  validation {
    condition     = can(regex("^[a-zA-Z0-9-]+$", var.name))
    error_message = "name may contain only letters, numbers, and hyphens."
  }
}

variable "vpc_id" {
  type        = string
  description = "VPC where the Network Firewall endpoints will be created."
}

variable "firewall_subnet_ids" {
  type        = set(string)
  description = "Dedicated firewall subnet IDs, one per Availability Zone."

  validation {
    condition     = length(var.firewall_subnet_ids) > 0
    error_message = "At least one dedicated firewall subnet is required."
  }
}

variable "allowed_source_cidrs" {
  type        = set(string)
  description = "IPv4 CIDRs allowed to reach the protected networks."

  validation {
    condition = length(var.allowed_source_cidrs) > 0 && alltrue([
      for cidr in var.allowed_source_cidrs : can(cidrhost(cidr, 0))
    ])
    error_message = "allowed_source_cidrs must contain at least one valid IPv4 CIDR."
  }
}

variable "protected_cidrs" {
  type        = set(string)
  description = "IPv4 CIDRs whose inbound traffic should be protected."

  validation {
    condition = length(var.protected_cidrs) > 0 && alltrue([
      for cidr in var.protected_cidrs : can(cidrhost(cidr, 0))
    ])
    error_message = "protected_cidrs must contain at least one valid IPv4 CIDR."
  }
}

variable "rule_group_capacity" {
  type        = number
  default     = 100
  description = "Capacity reserved for the stateful rule group."

  validation {
    condition     = var.rule_group_capacity >= 1
    error_message = "rule_group_capacity must be at least 1."
  }
}

variable "rule_sid" {
  type        = number
  default     = 1000001
  description = "Unique Suricata signature ID for the drop rule."
}

variable "delete_protection" {
  type        = bool
  default     = true
  description = "Prevent accidental firewall deletion."
}

variable "firewall_policy_change_protection" {
  type        = bool
  default     = true
  description = "Prevent accidental firewall policy changes."
}

variable "subnet_change_protection" {
  type        = bool
  default     = true
  description = "Prevent accidental firewall subnet changes."
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Tags applied to the firewall resources."
}
