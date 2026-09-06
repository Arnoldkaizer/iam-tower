# Network Firewall module

Creates an AWS Network Firewall with a stateful Suricata rule that drops IPv4 traffic from outside the approved source CIDRs when it targets the protected CIDRs.

This module creates the firewall, policy, and rule group. It does not modify route tables. Traffic is filtered only after the relevant VPC route tables send it through the firewall endpoint.

## Example

```hcl
module "network_firewall" {
  source = "./modules/network_firewall"

  name                = "iam-tower"
  vpc_id              = aws_vpc.main.id
  firewall_subnet_ids = [
    aws_subnet.firewall_a.id,
    aws_subnet.firewall_b.id,
  ]

  # Use the public CIDR that AWS actually sees for internet ingress.
  allowed_source_cidrs = ["203.0.113.10/32"]
  protected_cidrs      = [aws_vpc.main.cidr_block]

  tags = {
    Project = "IAM Security Tower"
  }
}
```

## Routing requirements

- Use dedicated subnets for the firewall endpoints.
- Add routes from protected subnet route tables to the firewall endpoint.
- Add the corresponding return routes so traffic is symmetric.
- For internet ingress, route traffic through the firewall before it reaches the protected subnet.
- Test in a non-production VPC first; incorrect routes can interrupt connectivity.

This is for VPC traffic enforcement. It does not restrict IAM or other AWS public API calls made from the internet. For that use case, apply an IAM policy or Organizations SCP with an `aws:SourceIp` condition as a separate control.
