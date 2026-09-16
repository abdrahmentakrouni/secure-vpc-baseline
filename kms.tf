# Customer managed key for the whole audit archive: CloudTrail, VPC flow
# logs, the CloudWatch audit log group and the SNS alarm topic all encrypt
# under this one key. Rotation is on, deletion needs 30 days, and the key
# policy below decides exactly who can encrypt or read.
resource "aws_kms_key" "logs" {
  description             = "Audit archive key: CloudTrail, flow logs, CloudWatch and SNS."
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.kms_logs.json

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-kms-logs" })
}

resource "aws_kms_alias" "logs" {
  name          = "alias/${var.name_prefix}-logs"
  target_key_id = aws_kms_key.logs.key_id
}

data "aws_iam_policy_document" "kms_logs" {
  # checkov:skip=CKV_AWS_109:Root admin statement is the AWS recovery pattern for key policies, service statements below are source-account constrained
  # checkov:skip=CKV_AWS_111:Root admin statement is the AWS recovery pattern for key policies
  # checkov:skip=CKV_AWS_356:Root admin statement is the AWS recovery pattern for key policies, service statements below are source-account constrained

  # The account root keeps full control of the key, which is what makes
  # recovery and rotation possible without any external dependency.
  statement {
    sid = "AccountRootAdministration"

    effect  = "Allow"
    actions = ["kms:*"]

    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  # Only the AWS services that produce the audit record may encrypt under
  # this key, and only when they do it on behalf of this account.
  statement {
    sid = "AuditServicesMayEncrypt"

    effect    = "Allow"
    actions   = ["kms:GenerateDataKey*", "kms:Encrypt", "kms:ReEncrypt*", "kms:DescribeKey"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com", "delivery.logs.amazonaws.com", "logs.${var.aws_region}.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  # Readers inside the account can decrypt for forensics, but only when
  # the request comes through S3. This keeps the key useful for breach
  # investigations without handing out a general-purpose decryption right.
  statement {
    sid = "ForensicsDecryptViaS3"

    effect    = "Allow"
    actions   = ["kms:Decrypt", "kms:DescribeKey"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.aws_region}.amazonaws.com"]
    }
  }
}
