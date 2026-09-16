# ------------------------------------------------------------------
# Dual firewall, layer 1: security groups (stateful, per resource).
# Rules reference other security groups instead of CIDR blocks, so a
# host can only be reached by the exact role that is allowed to reach
# it, no matter which subnet it lands in. Rules live as standalone
# rule resources, which keeps the groups acyclic and lets the ALB
# talk to the app tier while the app tier talks back on return ports.
# ------------------------------------------------------------------

# Edge: the only thing the internet can talk to.
resource "aws_security_group" "alb" {
  # checkov:skip=CKV2_AWS_5:Baseline module, groups attach to workloads deployed on top of this stack
  name_prefix = "${var.name_prefix}-alb-"
  description = "Edge tier: TLS terminus for the public load balancer."
  vpc_id      = aws_vpc.main.id

  lifecycle {
    create_before_destroy = true
  }

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-sg-alb" })
}

resource "aws_vpc_security_group_ingress_rule" "alb_https" {
  security_group_id = aws_security_group.alb.id
  description       = "HTTPS from the internet, TLS terminated at the load balancer"

  cidr_ipv4   = "0.0.0.0/0"
  ip_protocol = "tcp"
  from_port   = 443
  to_port     = 443
}

resource "aws_vpc_security_group_egress_rule" "alb_to_app" {
  security_group_id = aws_security_group.alb.id
  description       = "Forward to the application tier on its service port"

  referenced_security_group_id = aws_security_group.app.id
  ip_protocol                  = "tcp"
  from_port                    = 8080
  to_port                      = 8080
}

# Application tier: reached by the ALB, reaches the database, nothing else.
resource "aws_security_group" "app" {
  # checkov:skip=CKV2_AWS_5:Baseline module, groups attach to workloads deployed on top of this stack
  name_prefix = "${var.name_prefix}-app-"
  description = "Application tier: inbound from the load balancer only, no direct internet path in."
  vpc_id      = aws_vpc.main.id

  lifecycle {
    create_before_destroy = true
  }

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-sg-app" })
}

resource "aws_vpc_security_group_ingress_rule" "app_from_alb" {
  security_group_id = aws_security_group.app.id
  description       = "Service traffic from the load balancer security group"

  referenced_security_group_id = aws_security_group.alb.id
  ip_protocol                  = "tcp"
  from_port                    = 8080
  to_port                      = 8080
}

resource "aws_vpc_security_group_egress_rule" "app_to_data" {
  security_group_id = aws_security_group.app.id
  description       = "PostgreSQL to the data tier"

  referenced_security_group_id = aws_security_group.data.id
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
}

# Package updates through the NAT gateways and traffic to the SSM and
# S3 VPC endpoints. HTTPS only: the NACL layer carries the same rule.
resource "aws_vpc_security_group_egress_rule" "app_egress_tls" {
  security_group_id = aws_security_group.app.id
  description       = "TLS for package updates and VPC endpoints"

  cidr_ipv4   = "0.0.0.0/0"
  ip_protocol = "tcp"
  from_port   = 443
  to_port     = 443
}

# Data tier: reached by the app tier only. No egress except TLS to S3
# through the gateway endpoint, which is how encrypted backups leave
# the tier without any internet route existing.
resource "aws_security_group" "data" {
  # checkov:skip=CKV2_AWS_5:Baseline module, groups attach to workloads deployed on top of this stack
  name_prefix = "${var.name_prefix}-data-"
  description = "Data tier: inbound from the application tier only, no internet route in or out."
  vpc_id      = aws_vpc.main.id

  lifecycle {
    create_before_destroy = true
  }

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-sg-data" })
}

resource "aws_vpc_security_group_ingress_rule" "data_from_app" {
  security_group_id = aws_security_group.data.id
  description       = "PostgreSQL from the application tier security group"

  referenced_security_group_id = aws_security_group.app.id
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
}

resource "aws_vpc_security_group_egress_rule" "data_to_s3" {
  security_group_id = aws_security_group.data.id
  description       = "TLS to S3 through the gateway endpoint, for encrypted backups"

  prefix_list_id = aws_vpc_endpoint.s3.prefix_list_id
  ip_protocol    = "tcp"
  from_port      = 443
  to_port        = 443
}

# Interface endpoints accept TLS from anywhere inside the VPC, the
# endpoint network interfaces never initiate connections themselves.
resource "aws_security_group" "endpoints" {
  # checkov:skip=CKV2_AWS_5:Baseline module, groups attach to workloads deployed on top of this stack
  count = var.enable_ssm_endpoints ? 1 : 0

  name_prefix = "${var.name_prefix}-endpoints-"
  description = "Interface endpoints: accept TLS from inside the VPC only."
  vpc_id      = aws_vpc.main.id

  lifecycle {
    create_before_destroy = true
  }

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-sg-endpoints" })
}

resource "aws_vpc_security_group_ingress_rule" "endpoints_from_vpc" {
  count = var.enable_ssm_endpoints ? 1 : 0

  security_group_id = aws_security_group.endpoints[0].id
  description       = "TLS from the VPC to the endpoint network interfaces"

  cidr_ipv4   = var.vpc_cidr
  ip_protocol = "tcp"
  from_port   = 443
  to_port     = 443
}

# ------------------------------------------------------------------
# Dual firewall, layer 2: network ACLs (stateless, per subnet).
# These are the coarse backstop that catches misconfigured security
# groups. Rule numbers jump in steps of 20 so single rules can be
# inserted later without renumbering. Anything not allowed here is
# denied by the implicit final rule.
# ------------------------------------------------------------------

locals {
  # Public tier: HTTPS in, replies out, forwards to the app tier.
  nacl_public_ingress = [
    { no = 100, from = 443, to = 443, cidr = "0.0.0.0/0" },
    { no = 200, from = 1024, to = 65535, cidr = "0.0.0.0/0" },
  ]
  nacl_public_egress = [
    { no = 100, from = 8080, to = 8080, cidr = var.vpc_cidr },
    { no = 200, from = 1024, to = 65535, cidr = "0.0.0.0/0" },
  ]

  # App tier: service port from the public subnets, everything else is
  # egress-limited. The ephemeral rules exist because NACLs are
  # stateless; the security groups above carry the real precision.
  nacl_app_ingress = concat(
    [
      for i in range(var.az_count) : {
        no   = 100 + i * 20,
        from = 8080,
        to   = 8080,
        cidr = local.public_subnet_cidrs[i],
      }
    ],
    [
      { no = 300, from = 1024, to = 65535, cidr = "0.0.0.0/0" },
    ],
  )
  nacl_app_egress = concat(
    [
      for i in range(var.az_count) : {
        no   = 100 + i * 20,
        from = 5432,
        to   = 5432,
        cidr = local.data_subnet_cidrs[i],
      }
    ],
    [
      { no = 200, from = 443, to = 443, cidr = "0.0.0.0/0" },
      { no = 220, from = 80, to = 80, cidr = "0.0.0.0/0" },
      { no = 300, from = 1024, to = 65535, cidr = "0.0.0.0/0" },
    ],
  )

  # Data tier: database port from the app subnets only, egress limited
  # to TLS. Port 443 shows public S3 IPs at this layer because the
  # gateway endpoint routes S3 traffic without NAT, plus the SSM
  # endpoint interfaces inside the VPC.
  nacl_data_ingress = concat(
    [
      for i in range(var.az_count) : {
        no   = 100 + i * 20,
        from = 5432,
        to   = 5432,
        cidr = local.app_subnet_cidrs[i],
      }
    ],
    [
      { no = 300, from = 1024, to = 65535, cidr = var.vpc_cidr },
    ],
  )
  nacl_data_egress = [
    { no = 100, from = 443, to = 443, cidr = "0.0.0.0/0" },
    { no = 200, from = 1024, to = 65535, cidr = var.vpc_cidr },
  ]
}

resource "aws_network_acl" "public" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = [for s in aws_subnet.public : s.id]

  dynamic "ingress" {
    for_each = local.nacl_public_ingress
    content {
      rule_no    = ingress.value.no
      protocol   = "tcp"
      action     = "allow"
      from_port  = ingress.value.from
      to_port    = ingress.value.to
      cidr_block = ingress.value.cidr
    }
  }

  dynamic "egress" {
    for_each = local.nacl_public_egress
    content {
      rule_no    = egress.value.no
      protocol   = "tcp"
      action     = "allow"
      from_port  = egress.value.from
      to_port    = egress.value.to
      cidr_block = egress.value.cidr
    }
  }

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-nacl-public" })
}

resource "aws_network_acl" "app" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = [for s in aws_subnet.app : s.id]

  dynamic "ingress" {
    for_each = local.nacl_app_ingress
    content {
      rule_no    = ingress.value.no
      protocol   = "tcp"
      action     = "allow"
      from_port  = ingress.value.from
      to_port    = ingress.value.to
      cidr_block = ingress.value.cidr
    }
  }

  dynamic "egress" {
    for_each = local.nacl_app_egress
    content {
      rule_no    = egress.value.no
      protocol   = "tcp"
      action     = "allow"
      from_port  = egress.value.from
      to_port    = egress.value.to
      cidr_block = egress.value.cidr
    }
  }

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-nacl-app" })
}

resource "aws_network_acl" "data" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = [for s in aws_subnet.data : s.id]

  dynamic "ingress" {
    for_each = local.nacl_data_ingress
    content {
      rule_no    = ingress.value.no
      protocol   = "tcp"
      action     = "allow"
      from_port  = ingress.value.from
      to_port    = ingress.value.to
      cidr_block = ingress.value.cidr
    }
  }

  dynamic "egress" {
    for_each = local.nacl_data_egress
    content {
      rule_no    = egress.value.no
      protocol   = "tcp"
      action     = "allow"
      from_port  = egress.value.from
      to_port    = egress.value.to
      cidr_block = egress.value.cidr
    }
  }

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-nacl-data" })
}
