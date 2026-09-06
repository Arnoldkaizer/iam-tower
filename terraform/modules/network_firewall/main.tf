terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

resource "aws_networkfirewall_rule_group" "out_of_range_sources" {
  capacity = var.rule_group_capacity
  name     = "${var.name}-out-of-range-sources"
  type     = "STATEFUL"

  rule_group {
    rule_variables {
      ip_sets {
        key = "TRUSTED_SOURCES"

        ip_set {
          definition = var.allowed_source_cidrs
        }
      }

      ip_sets {
        key = "PROTECTED_NETWORKS"

        ip_set {
          definition = var.protected_cidrs
        }
      }
    }

    rules_source {
      rules_string = <<-EOT
        drop ip !$TRUSTED_SOURCES any -> $PROTECTED_NETWORKS any (msg:"Drop traffic from outside approved source ranges"; sid:${var.rule_sid}; rev:1;)
      EOT
    }

    stateful_rule_options {
      rule_order = "STRICT_ORDER"
    }
  }

  tags = var.tags
}

resource "aws_networkfirewall_firewall_policy" "this" {
  name = "${var.name}-policy"

  firewall_policy {
    stateless_default_actions          = ["aws:forward_to_sfe"]
    stateless_fragment_default_actions = ["aws:forward_to_sfe"]
    stateful_default_actions           = []

    stateful_engine_options {
      rule_order = "STRICT_ORDER"
    }

    stateful_rule_group_reference {
      priority     = 10
      resource_arn = aws_networkfirewall_rule_group.out_of_range_sources.arn
    }
  }

  tags = var.tags
}

resource "aws_networkfirewall_firewall" "this" {
  name                = var.name
  firewall_policy_arn = aws_networkfirewall_firewall_policy.this.arn
  vpc_id              = var.vpc_id

  dynamic "subnet_mapping" {
    for_each = toset(var.firewall_subnet_ids)

    content {
      subnet_id = subnet_mapping.value
    }
  }

  delete_protection                 = var.delete_protection
  firewall_policy_change_protection = var.firewall_policy_change_protection
  subnet_change_protection          = var.subnet_change_protection

  tags = var.tags
}
