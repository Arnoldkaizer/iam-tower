variable "aws_region" {
  type        = string
  default     = "us-east-1"
  description = "AWS Region where IAM Security Tower infrastructure will be deployed"
}

variable "environment" {
  type        = string
  default     = "production"
  description = "Deployment environment name (e.g., development, staging, production)"
}

variable "alert_email" {
  type        = string
  default     = ""
  description = "Email address to receive high-risk incident alerts (optional)"
}

variable "name_prefix" {
  type        = string
  default     = "iam-tower"
  description = "Prefix applied to inspection network resource names."
}

variable "vpc_cidr" {
  type        = string
  default     = "10.40.0.0/16"
  description = "CIDR block for the inspection VPC."
}

variable "firewall_subnet_cidrs" {
  type        = list(string)
  default     = ["10.40.1.0/24", "10.40.2.0/24"]
  description = "Dedicated firewall subnet CIDRs, one per Availability Zone."
}

variable "protected_subnet_cidrs" {
  type        = list(string)
  default     = ["10.40.11.0/24", "10.40.12.0/24"]
  description = "Protected subnet CIDRs, one per Availability Zone."
}

variable "public_subnet_cidrs" {
  type        = list(string)
  default     = ["10.40.21.0/24", "10.40.22.0/24"]
  description = "Public subnet CIDRs for per-AZ NAT gateways."
}

variable "allowed_source_cidrs" {
  type        = set(string)
  description = "Public IPv4 CIDRs allowed to reach protected subnets."

  validation {
    condition = length(var.allowed_source_cidrs) > 0 && alltrue([
      for cidr in var.allowed_source_cidrs : can(cidrhost(cidr, 0))
    ])
    error_message = "Set allowed_source_cidrs to one or more valid public IPv4 CIDRs."
  }
}
