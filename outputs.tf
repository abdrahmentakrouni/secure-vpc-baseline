output "vpc_id" {
  description = "ID of the VPC."
  value       = aws_vpc.main.id
}

output "vpc_cidr" {
  description = "CIDR block of the VPC."
  value       = aws_vpc.main.cidr_block
}

output "public_subnet_ids" {
  description = "Public subnet IDs, keyed by availability zone."
  value       = { for az, s in aws_subnet.public : az => s.id }
}

output "app_subnet_ids" {
  description = "Private application subnet IDs, keyed by availability zone."
  value       = { for az, s in aws_subnet.app : az => s.id }
}

output "data_subnet_ids" {
  description = "Private data subnet IDs, keyed by availability zone. No internet route exists for these."
  value       = { for az, s in aws_subnet.data : az => s.id }
}

output "nat_elastic_ips" {
  description = "Public elastic IPs of the NAT gateways, keyed by availability zone."
  value       = { for i in range(length(aws_eip.nat)) : local.azs[i] => aws_eip.nat[i].public_ip }
}

output "log_archive_bucket" {
  description = "Name of the immutable log archive bucket (CloudTrail and flow logs)."
  value       = aws_s3_bucket.log_archive.id
}

output "cloudtrail_arn" {
  description = "ARN of the multi-region audit trail."
  value       = aws_cloudtrail.main.arn
}

output "kms_key_arn" {
  description = "ARN of the customer managed key that encrypts the audit archive."
  value       = aws_kms_key.logs.arn
}

output "security_alerts_topic" {
  description = "SNS topic that receives security alarm notifications."
  value       = aws_sns_topic.security_alerts.arn
}
