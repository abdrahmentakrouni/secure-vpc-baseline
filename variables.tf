variable "aws_region" {
  description = "AWS region the network is deployed into."
  type        = string
  default     = "eu-west-3"
}

variable "name_prefix" {
  description = "Prefix used for every resource name in this stack."
  type        = string
  default     = "core"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,20}$", var.name_prefix))
    error_message = "Use 2 to 21 lowercase letters, digits or dashes, starting with a letter."
  }
}

variable "vpc_cidr" {
  description = "CIDR block of the VPC. Three tiers of /20 slices are carved out of it per AZ."
  type        = string
  default     = "10.40.0.0/16"

  validation {
    condition     = can(cidrnetmask(var.vpc_cidr)) && tonumber(split("/", var.vpc_cidr)[1]) >= 20 && tonumber(split("/", var.vpc_cidr)[1]) <= 24
    error_message = "Provide a valid IPv4 CIDR with a prefix between /20 and /24 so the tier slices fit."
  }
}

variable "az_count" {
  description = "Number of availability zones used for each tier."
  type        = number
  default     = 2

  validation {
    condition     = var.az_count >= 2 && var.az_count <= 3
    error_message = "Use between 2 and 3 availability zones."
  }
}

variable "single_nat_gateway" {
  description = "Run one shared NAT gateway instead of one per AZ. Cheaper for dev, but it is a single point of failure across the tier."
  type        = bool
  default     = false
}

variable "enable_ssm_endpoints" {
  description = "Create the SSM interface endpoints so private instances are managed without any bastion host and without any open SSH port."
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "CloudWatch retention for the audit log group."
  type        = number
  default     = 365
}

variable "object_lock_retention_days" {
  description = "Object-lock retention applied to every object written to the log archive bucket. Logs stay immutable for this long."
  type        = number
  default     = 30
}

variable "alarm_email" {
  description = "Email address that receives security alarm notifications. Leave null to keep the SNS topic silent."
  type        = string
  default     = null
}

variable "tags" {
  description = "Extra tags merged into every resource."
  type        = map(string)
  default     = {}
}
