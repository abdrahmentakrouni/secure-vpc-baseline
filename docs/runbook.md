# Runbook

Operational handbook: deploy, verify, investigate, tear down.

## Prerequisites

- Terraform >= 1.5 (tested with 1.9.8)
- AWS CLI v2, configured with credentials that can manage VPC, EC2
  (subnets/NACLs/flow logs), S3, KMS, CloudTrail, CloudWatch, SNS and IAM
- An email inbox you control, if you want the alarm subscription

## One-time: remote state backend

The state file carries account IDs and resource identifiers. Create a
locked S3 backend before the first apply (region adjusted to taste):

```bash
aws s3api create-bucket --bucket my-terraform-state-123456789012-eu-west-3 \
  --region eu-west-3 --create-bucket-configuration LocationConstraint=eu-west-3

aws s3api put-bucket-versioning --bucket my-terraform-state-123456789012-eu-west-3 \
  --versioning-configuration Status=Enabled

aws s3api put-bucket-encryption --bucket my-terraform-state-123456789012-eu-west-3 \
  --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms"}}]}'

aws dynamodb create-table --table-name terraform-locks \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST
```

Then copy `backend.tf.example` to `backend.tf` and fill in the bucket.

## Deploy

```bash
cp terraform.tfvars.example terraform.tfvars   # edit values first
terraform init
terraform plan
terraform apply                                # ~10 minutes
```

If `alarm_email` is set, AWS sends a confirmation mail; the subscription
stays "pending confirmation" until it is clicked.

## Verify the build

Run through this after every apply. Every command should look right:

```bash
# Trail is multi-region, validating, and logging
aws cloudtrail describe-trails --trail-name-list core-audit-trail
aws cloudtrail get-trail-status --name core-audit-trail   # IsLogging: true

# Flow logs are attached and delivering
aws ec2 describe-flow-logs --filter Name=resource-id,Values=$(terraform output -raw vpc_id)

# The vault received its first log files
aws s3 ls s3://$(terraform output -raw log_archive_bucket)/AWSLogs/ --recursive | head
aws s3 ls s3://$(terraform output -raw log_archive_bucket)/vpc-flow-logs/ --recursive | head

# Key exists, rotation is on
aws kms describe-key --key-id alias/core-logs

# Alarms are armed
aws cloudwatch describe-alarms --alarm-names core-root-usage core-unauthorized-calls core-audit-tampering

# Data tier really has no internet route: these come back empty
aws ec2 describe-route-tables \
  --filters Name=tag:Name,Values=core-rt-data-* \
  --query 'RouteTables[].Routes'
```

An empty result is the correct result. The data route tables carry zero
routes, that is the whole point.

## Investigate: flow logs in Athena

Create a workgroup and a table over the vault's parquet files (adjust
bucket name and region):

```sql
CREATE EXTERNAL TABLE vpc_flow_logs (
  version int, account_id string, interface_id string, srcaddr string,
  dstaddr string, srcport int, dstport int, protocol int, packets bigint,
  bytes bigint, start bigint, `end` bigint, action string, log_status string,
  vpc_id string, subnet_id string, instance_id string, tcp_flags int,
  type string, pkt_src_aws_service string, pkt_dst_aws_service string
)
PARTITIONED BY (aws_account_id string, aws_region string, dt string)
STORED AS PARQUET
LOCATION 's3://<log-archive-bucket>/vpc-flow-logs/'
TBLPROPERTIES ('projection.enabled'='true',
  'projection.aws_account_id.type'='account-id',
  'projection.aws_region.type'='enum', 'projection.aws_region.values'='eu-west-3',
  'projection.dt.type'='date', 'projection.dt.format'='yyyy/MM/dd',
  'storage.location.template'='s3://<log-archive-bucket>/vpc-flow-logs/AWSLogs/${aws_account_id}/vpcflowlogs/${aws_region}/${dt}')
```

First queries for a bad morning (grab the subnet IDs first with
`terraform output -json app_subnet_ids` and `... data_subnet_ids`):

```sql
-- Who moved the most data out of the app tier?
SELECT srcaddr, dstaddr, sum(bytes) AS total_bytes, count(*) AS flows
FROM vpc_flow_logs
WHERE subnet_id IN ('subnet-APP-A', 'subnet-APP-B')
  AND dstaddr NOT LIKE '10.40.%'
  AND action = 'ACCEPT'
GROUP BY srcaddr, dstaddr ORDER BY total_bytes DESC LIMIT 20;

-- Every rejected packet around the data tier (lateral movement attempts)
SELECT start, srcaddr, dstaddr, dstport, action
FROM vpc_flow_logs
WHERE action = 'REJECT'
  AND subnet_id IN ('subnet-DATA-A', 'subnet-DATA-B')
ORDER BY start DESC LIMIT 100;

-- Who talks to the database tier besides the app tier?
SELECT DISTINCT srcaddr, dstport
FROM vpc_flow_logs
WHERE subnet_id IN ('subnet-DATA-A', 'subnet-DATA-B')
  AND dstport <> 5432;
```

CloudTrail questions ("who did this") run the same way over the
`AWSLogs/` prefix using the standard CloudTrail Athena table from the
AWS documentation.

## First 30 minutes of an incident

1. **Confirm the alarm** in SNS / CloudWatch; identify which of the
   three filters fired (root usage, unauthorized calls, trail tampering).
2. **Open CloudTrail** for the last 24h around the first event; note the
   principal, source IP and user agent of the earliest anomaly.
3. **Scope with flow logs**: run the exfiltration query and the
   rejected-flows query above; record the involved interface IDs.
4. **Check the audit chain**: `get-trail-status` (still logging?),
   log file validation result, any `StopLogging` events, object-lock
   state of recent vault objects.
5. **Contain at the network layer**: the SG chain is the emergency
   brake - tighten `app_egress_tls` to a prefix list or remove NAT
   routes for the affected AZ; both are one-commit, one-apply changes.
6. **Preserve evidence**: copy the relevant vault prefixes before any
   destructive action; the object lock has kept them intact until now,
   do not let cleanup be the thing that destroys them.

## Tear down

```bash
terraform destroy          # removes everything, including demo logs
```

The vault is not force-destroyable through the code; in a real estate it
lives in a separate audit account and never gets destroyed with the
network. Empty the two buckets first if a sandbox teardown insists.
