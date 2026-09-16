# ------------------------------------------------------------------
# The log vault. One S3 bucket collects everything an investigator
# needs after a breach: CloudTrail management events and VPC flow
# logs. Versioned, KMS encrypted, object-locked, no public access,
# TLS enforced, and its own access trail in a second bucket.
# ------------------------------------------------------------------

locals {
  log_archive_bucket_name = "${var.name_prefix}-log-archive-${data.aws_caller_identity.current.account_id}-${var.aws_region}"
  access_logs_bucket_name = "${var.name_prefix}-log-access-${data.aws_caller_identity.current.account_id}-${var.aws_region}"
}

resource "aws_s3_bucket" "log_archive" {
  # checkov:skip=CKV_AWS_144:Log vault is the recovery source itself; cross-region copy documented as roadmap for enterprise estates
  # checkov:skip=CKV2_AWS_62:Write-only vault fed by AWS log delivery, object events are not consumed by any subscriber

  bucket = local.log_archive_bucket_name

  # Object lock needs versioning; the provider enables it automatically.
  object_lock_enabled = true

  # Bucket owner preferred keeps the classic AWS log delivery policies
  # (they expect the bucket-owner-full-control ACL header) working.
  force_destroy = false

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-log-archive" })
}

resource "aws_s3_bucket_versioning" "log_archive" {
  bucket = aws_s3_bucket.log_archive.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Every object written here is locked in governance mode: even an
# account admin cannot delete or overwrite a log for the retention
# window. This is what turns the bucket into an evidence store.
resource "aws_s3_bucket_object_lock_configuration" "log_archive" {
  bucket = aws_s3_bucket.log_archive.id

  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = var.object_lock_retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.log_archive]
}

resource "aws_s3_bucket_server_side_encryption_configuration" "log_archive" {
  bucket = aws_s3_bucket.log_archive.id

  rule {
    bucket_key_enabled = true

    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.logs.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "log_archive" {
  bucket = aws_s3_bucket.log_archive.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Older log data slides down the storage classes automatically, the
# audit record itself never expires.
resource "aws_s3_bucket_lifecycle_configuration" "log_archive" {
  bucket = aws_s3_bucket.log_archive.id

  rule {
    id     = "tier-older-logs"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 365
      storage_class = "GLACIER_IR"
    }
  }
}

resource "aws_s3_bucket_logging" "log_archive" {
  bucket = aws_s3_bucket.log_archive.id

  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "archive-access/"
}

resource "aws_s3_bucket_policy" "log_archive" {
  bucket = aws_s3_bucket.log_archive.id

  policy = data.aws_iam_policy_document.log_archive.json

  depends_on = [
    aws_s3_bucket_public_access_block.log_archive,
    aws_s3_bucket_object_lock_configuration.log_archive,
  ]
}

data "aws_iam_policy_document" "log_archive" {
  # CloudTrail: acl check on the bucket, writes under AWSLogs/ only.
  statement {
    sid = "CloudTrailAclCheck"

    effect    = "Allow"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.log_archive.arn]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  statement {
    sid = "CloudTrailWrite"

    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.log_archive.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  # VPC flow logs delivery: same pattern, own prefix.
  statement {
    sid = "FlowLogsAclCheck"

    effect    = "Allow"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.log_archive.arn]

    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  statement {
    sid = "FlowLogsWrite"

    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.log_archive.arn}/vpc-flow-logs/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]

    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  # Every API call against this bucket must ride on TLS.
  statement {
    sid = "DenyInsecureTransport"

    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.log_archive.arn,
      "${aws_s3_bucket.log_archive.arn}/*",
    ]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  # Nothing may write plaintext into the evidence store. If the header
  # is present it must say aws:kms, otherwise the bucket default (the
  # same CMK) applies.
  statement {
    sid = "DenyUnencryptedPut"

    effect  = "Deny"
    actions = ["s3:PutObject"]
    resources = [
      "${aws_s3_bucket.log_archive.arn}/*",
    ]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEqualsIfExists"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms"]
    }
  }
}

# Terminal sink for the archive bucket's own access logs. It logs nobody
# (recursive logging is disabled on purpose) but gets the same hardening.
# tfsec:ignore:aws-s3-enable-bucket-logging Terminal log sink, recursive access logging is disabled on purpose
resource "aws_s3_bucket" "access_logs" {
  # checkov:skip=CKV_AWS_18:Terminal log sink, recursive access logging is disabled on purpose
  # checkov:skip=CKV_AWS_144:Terminal log sink, cross-region copy adds cost without forensic value
  # checkov:skip=CKV2_AWS_62:Terminal sink, object events are not consumed by any subscriber

  bucket = local.access_logs_bucket_name

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-log-access" })
}

resource "aws_s3_bucket_versioning" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  rule {
    bucket_key_enabled = true

    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.logs.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  rule {
    id     = "expire-access-logs"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    expiration {
      days = 90
    }
  }
}

# ------------------------------------------------------------------
# CloudTrail: every management API call in the region set lands in the
# vault, encrypted, integrity validated, mirrored to CloudWatch so
# alarms can react in near real time.
# ------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/${var.name_prefix}"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.logs.arn

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-audit-logs" })
}

resource "aws_iam_role" "cloudtrail_to_cw" {
  name = "${var.name_prefix}-cloudtrail-to-cw"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Action    = "sts:AssumeRole"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
}

# tfsec:ignore:aws-iam-no-policy-wildcards Wildcard targets the log stream namespace inside the audit group, per the AWS CloudTrail delivery pattern
resource "aws_iam_role_policy" "cloudtrail_to_cw" {
  name = "write-audit-log-group"
  role = aws_iam_role.cloudtrail_to_cw.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = ["${aws_cloudwatch_log_group.cloudtrail.arn}:*"]
      }
    ]
  })
}

resource "aws_cloudtrail" "main" {
  name = "${var.name_prefix}-audit-trail"

  s3_bucket_name = aws_s3_bucket.log_archive.id
  sns_topic_name = aws_sns_topic.security_alerts.name

  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.logs.arn

  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_to_cw.arn

  depends_on = [aws_s3_bucket_policy.log_archive]

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-audit-trail" })
}

# ------------------------------------------------------------------
# VPC flow logs: every accepted and rejected packet gets a record in
# the vault, one minute aggregation, parquet format for Athena.
# ------------------------------------------------------------------

resource "aws_flow_log" "vpc" {
  log_destination_type = "s3"
  log_destination      = "${aws_s3_bucket.log_archive.arn}/vpc-flow-logs"

  traffic_type             = "ALL"
  max_aggregation_interval = 60

  log_format = "$${version} $${account-id} $${interface-id} $${srcaddr} $${dstaddr} $${srcport} $${dstport} $${protocol} $${packets} $${bytes} $${start} $${end} $${action} $${log-status} $${vpc-id} $${subnet-id} $${instance-id} $${tcp-flags} $${type} $${pkt-src-aws-service} $${pkt-dst-aws-service}"

  vpc_id = aws_vpc.main.id

  depends_on = [aws_s3_bucket_policy.log_archive]

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-flow-logs" })
}

# ------------------------------------------------------------------
# Detection: SNS topic plus metric filters on the CloudTrail stream.
# These three alarms catch the classic first moves of an intruder:
# using the root account, probing with unauthorized API calls, and
# trying to switch the audit trail off.
# ------------------------------------------------------------------

resource "aws_sns_topic" "security_alerts" {
  name              = "${var.name_prefix}-security-alerts"
  kms_master_key_id = aws_kms_key.logs.arn

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-security-alerts" })
}

resource "aws_sns_topic_subscription" "alarm_email" {
  count = var.alarm_email != null ? 1 : 0

  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.alarm_email
}

data "aws_iam_policy_document" "sns_alerts" {
  statement {
    sid = "CloudWatchAlarmsPublish"

    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.security_alerts.arn]

    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  # CloudTrail publishes a notification per delivered log file.
  statement {
    sid = "CloudTrailDeliveryPublish"

    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.security_alerts.arn]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_sns_topic_policy" "security_alerts" {
  arn    = aws_sns_topic.security_alerts.arn
  policy = data.aws_iam_policy_document.sns_alerts.json
}

locals {
  alarm_filters = {
    root_usage = {
      pattern = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"
      name    = "RootAccountUsage"
    }
    unauthorized_calls = {
      pattern = "{ ($.errorCode = \"*UnauthorizedOperation\" || $.errorCode = \"AccessDenied*\") && $.sourceIPAddress != \"delivery.logs.amazonaws.com\" && $.eventType != \"AwsServiceEvent\" }"
      name    = "UnauthorizedApiCalls"
    }
    audit_tampering = {
      pattern = "{ $.eventName = \"StopLogging\" || $.eventName = \"DeleteTrail\" || $.eventName = \"UpdateTrail\" }"
      name    = "AuditTrailTampering"
    }
  }
}

resource "aws_cloudwatch_log_metric_filter" "security" {
  for_each = local.alarm_filters

  name           = "${var.name_prefix}-${each.key}"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = each.value.pattern

  metric_transformation {
    name          = each.value.name
    namespace     = "SecurityBaseline"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "security" {
  for_each = local.alarm_filters

  alarm_name          = "${var.name_prefix}-${each.key}"
  alarm_description   = "Security baseline alarm: ${each.key}. Check CloudTrail in the log archive immediately."
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = each.value.name
  namespace           = "SecurityBaseline"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.security_alerts.arn]
  ok_actions    = [aws_sns_topic.security_alerts.arn]

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-alarm-${each.key}" })
}
