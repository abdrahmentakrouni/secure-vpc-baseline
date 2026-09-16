resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-vpc" })
}

# The VPC ships with a default security group and a default NACL that allow
# everything. Both are locked down below, so anything launched without an
# explicit firewall rule set stays dark instead of silently talking.

resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id

  # No ingress and no egress: deny everything, statefully.
  ingress = []
  egress  = []

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-sg-default-deny" })
}

resource "aws_default_network_acl" "default" {
  default_network_acl_id = aws_vpc.main.default_network_acl_id

  # No rules configured: every subnet that is not explicitly associated
  # with one of the tier NACLs below is cut off at layer 3.
  tags = merge(local.common_tags, { Name = "${var.name_prefix}-nacl-default-deny" })
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-igw" })
}

# Public tier: only the load balancer and the NAT gateways live here.
# Nothing gets an auto-assigned public IP, addresses stay explicit.
resource "aws_subnet" "public" {
  for_each = { for idx, cidr in local.public_subnet_cidrs : local.azs[idx] => cidr }

  vpc_id                  = aws_vpc.main.id
  cidr_block              = each.value
  availability_zone       = each.key
  map_public_ip_on_launch = false

  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-public-${each.key}"
    Tier = "public"
  })
}

# Application tier: no auto public IPs, inbound only from the ALB.
resource "aws_subnet" "app" {
  for_each = { for idx, cidr in local.app_subnet_cidrs : local.azs[idx] => cidr }

  vpc_id                  = aws_vpc.main.id
  cidr_block              = each.value
  availability_zone       = each.key
  map_public_ip_on_launch = false

  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-app-${each.key}"
    Tier = "app"
  })
}

# Data tier: databases and stateful stores. Same treatment, and the
# route table attached below has no internet route of any kind.
resource "aws_subnet" "data" {
  for_each = { for idx, cidr in local.data_subnet_cidrs : local.azs[idx] => cidr }

  vpc_id                  = aws_vpc.main.id
  cidr_block              = each.value
  availability_zone       = each.key
  map_public_ip_on_launch = false

  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-data-${each.key}"
    Tier = "data"
  })
}

# One NAT gateway per AZ by default, so a single AZ failure does not take
# the app tier's outbound path down with it. Set single_nat_gateway for
# cheap dev stacks, never for production.
resource "aws_eip" "nat" {
  count = var.single_nat_gateway ? 1 : var.az_count

  domain = "vpc"

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-nat-${count.index}" })
}

resource "aws_nat_gateway" "main" {
  count = var.single_nat_gateway ? 1 : var.az_count

  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[local.azs[count.index]].id

  depends_on = [aws_internet_gateway.main]

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-nat-${local.azs[count.index]}" })
}

# Public route table: the only path between this VPC and the internet.
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-rt-public" })
}

resource "aws_route" "public_internet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.main.id
}

resource "aws_route_table_association" "public" {
  for_each = aws_subnet.public

  subnet_id      = each.value.id
  route_table_id = aws_route_table.public.id
}

# App tier: outbound through its own AZ's NAT gateway, nothing inbound.
resource "aws_route_table" "app" {
  for_each = aws_subnet.app

  vpc_id = aws_vpc.main.id

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-rt-app-${each.key}" })
}

resource "aws_route" "app_nat" {
  for_each = aws_route_table.app

  route_table_id         = each.value.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = var.single_nat_gateway ? aws_nat_gateway.main[0].id : aws_nat_gateway.main[index(local.azs, each.key)].id
}

resource "aws_route_table_association" "app" {
  for_each = aws_subnet.app

  subnet_id      = each.value.id
  route_table_id = aws_route_table.app[each.key].id
}

# Data tier: the route table stays empty. No IGW, no NAT, no exceptions.
# The only way out is the S3 gateway endpoint declared in endpoints.tf.
resource "aws_route_table" "data" {
  for_each = aws_subnet.data

  vpc_id = aws_vpc.main.id

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-rt-data-${each.key}" })
}

resource "aws_route_table_association" "data" {
  for_each = aws_subnet.data

  subnet_id      = each.value.id
  route_table_id = aws_route_table.data[each.key].id
}
