data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_caller_identity" "current" {}

locals {
  azs = slice(data.aws_availability_zones.available.names, 0, var.az_count)

  # Three tiers, one /20 slice per AZ, carved out of the VPC CIDR:
  #   public  -> load balancers and NAT gateways, the only internet-facing slice
  #   app     -> application servers, inbound from the ALB only
  #   data    -> databases, no route to or from the internet at all
  public_subnet_cidrs = [for i in range(var.az_count) : cidrsubnet(var.vpc_cidr, 4, i)]
  app_subnet_cidrs    = [for i in range(var.az_count) : cidrsubnet(var.vpc_cidr, 4, i + var.az_count)]
  data_subnet_cidrs   = [for i in range(var.az_count) : cidrsubnet(var.vpc_cidr, 4, i + 2 * var.az_count)]

  common_tags = merge(var.tags, {
    ManagedBy = "terraform"
    Project   = "secure-vpc-baseline"
  })
}
