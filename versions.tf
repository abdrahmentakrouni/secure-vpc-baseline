terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  # Every resource carries the same baseline tags, so audit tooling and
  # cost reports can group by project without any manual bookkeeping.
  default_tags {
    tags = local.common_tags
  }
}
