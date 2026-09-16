# S3 gateway endpoint: free of charge, and it gives the app and data tiers
# a private path to S3. This is what lets encrypted backups leave the data
# tier even though that tier has no internet route at all.
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"

  # App and data route tables only. The public tier talks to S3 over its
  # own internet path and does not need this.
  route_table_ids = concat(
    [for rt in aws_route_table.app : rt.id],
    [for rt in aws_route_table.data : rt.id],
  )

  # Same-account principals only: even through the endpoint, nobody from
  # outside this account gets to walk the S3 API.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "SameAccountAccessOnly"
        Effect    = "Allow"
        Principal = { AWS = "*" }
        Action    = ["s3:*"]
        Resource  = ["*"]
        Condition = {
          StringEquals = {
            "aws:PrincipalAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-ep-s3" })
}

# SSM interface endpoints: private instances stay fully manageable through
# Session Manager and Run Command, with no bastion host and no open SSH
# port anywhere in the network. Toggle with enable_ssm_endpoints, roughly
# three endpoints per AZ at about one cent per hour each.
# The endpoint security group is declared in security.tf together with
# the rest of the firewall layer.
resource "aws_vpc_endpoint" "ssm" {
  count = var.enable_ssm_endpoints ? 1 : 0

  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.ssm"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [for s in aws_subnet.app : s.id]
  security_group_ids  = [aws_security_group.endpoints[0].id]
  private_dns_enabled = true

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-ep-ssm" })
}

resource "aws_vpc_endpoint" "ssmmessages" {
  count = var.enable_ssm_endpoints ? 1 : 0

  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.ssmmessages"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [for s in aws_subnet.app : s.id]
  security_group_ids  = [aws_security_group.endpoints[0].id]
  private_dns_enabled = true

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-ep-ssmmessages" })
}

resource "aws_vpc_endpoint" "ec2messages" {
  count = var.enable_ssm_endpoints ? 1 : 0

  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.ec2messages"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [for s in aws_subnet.app : s.id]
  security_group_ids  = [aws_security_group.endpoints[0].id]
  private_dns_enabled = true

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-ep-ec2messages" })
}
