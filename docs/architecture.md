# Architecture

## The tiers

The VPC is carved into three tiers, each tier gets one /20 slice per
availability zone. With the default `vpc_cidr = 10.40.0.0/16` and
`az_count = 2`:

| Tier | AZ a | AZ b | Purpose | Internet path |
|---|---|---|---|---|
| public | 10.40.0.0/20 | 10.40.16.0/20 | ALB nodes, NAT gateways | In: HTTPS only, out: full |
| app | 10.40.32.0/20 | 10.40.48.0/20 | Application servers | Out via own-AZ NAT, in: ALB only |
| data | 10.40.64.0/20 | 10.40.80.0/20 | Databases, stateful stores | None. Empty route table |

The `cidrsubnet` math scales with `az_count`: set it to 3 and the tiers
become slices 0-2, 3-5 and 6-8 automatically. No manual CIDR renumbering.

## What gets created

| Kind | Count | Notes |
|---|---|---|
| VPC + IGW | 2 | DNS hostnames on, so SSM endpoints resolve privately |
| Subnets | 6 | Two per tier, `map_public_ip_on_launch = false` everywhere |
| NAT gateways + EIPs | 2 (or 1) | Per-AZ by default, `single_nat_gateway` for dev |
| Route tables | 7 | Public, app x AZ, data x AZ; the data tables have zero routes |
| VPC endpoints | 4 | S3 gateway (free) + SSM, SSM messages, EC2 messages (interface) |
| Security groups | 4 (+default) | ALB, app, data, endpoints; default group denies everything |
| NACLs | 3 (+default) | Public, app, data; default ACL denies everything |
| S3 buckets | 2 | Log vault + terminal access-log sink |
| KMS | 1 key + alias | Customer managed, auto-rotation, 30-day deletion window |
| CloudTrail | 1 trail | Multi-region, validation, SNS + CloudWatch delivery |
| Flow logs | 1 | Whole VPC, all traffic, 1-minute parquet to the vault |
| CloudWatch | 1 log group + 3 filters + 3 alarms | Root usage, unauthorized calls, trail tampering |
| SNS | 1 topic | Email subscription optional via `alarm_email` |

## Traffic flows

**Serving a user.** Browser hits the ALB on 443, TLS terminates at the
load balancer, the ALB forwards to any healthy app host on 8080. The SG
chain is referential: ALB SG may talk to app SG on 8080, nothing else may
talk to the app SG at all. Return traffic is stateful at the SG layer.

**App tier reaching the internet.** Package updates and similar egress
ride the NAT gateway of their own AZ. Ports are limited to 80/443 at the
SG layer, and the NACL layer allows nothing else. There is no path for
the internet to open a connection into the app tier; NAT is outbound only.

**Data tier reaching S3.** The S3 gateway endpoint is attached to the app
and data route tables. The data SG permits exactly one egress: TLS to the
S3 prefix list. This is deliberate - it is the channel the companion
project backup-vault uses to ship encrypted backups out of an otherwise
air-gapped tier. The endpoint policy additionally restricts S3 access to
same-account principals.

**Admin access.** There is no bastion host and no SSH port anywhere.
Private instances are managed through the three SSM interface endpoints
(Session Manager, Run Command), which also produce their own CloudTrail
records. Removing the bastion removes an entire class of attack surface.

**Everything observable.** CloudTrail captures management events in all
regions and ships them to the vault. VPC flow logs capture every accepted
and rejected packet at one-minute aggregation and ship parquet files to
the vault. CloudWatch carries a live copy of the trail for the alarms.
The SNS topic fans out root-usage, unauthorized-API and trail-tampering
alerts, and CloudTrail announces every new log file on the same topic.

## Design decisions

**1. /20 slices per tier.** 4,096 addresses per tier per AZ is more than
enough for most workloads and leaves the VPC CIDR headroom for future
subnets (a /18 carve-out, an EKS tier, whatever comes next).

**2. NAT per AZ, not shared.** A shared NAT is a single point of failure
for the whole app tier's outbound path. Two gateways cost about $33 a
month each; resilience is cheap compared to a 3 a.m. pager. The dev
toggle exists because a sandbox is not production.

**3. The data tier has no route at all.** Not "restricted" - none. The
route table is empty, so even a root shell on a data-tier host cannot
phone out except through the S3 endpoint. This is the strongest control
in the stack and it costs nothing.

**4. S3 gateway endpoint instead of nothing.** Free, region-local, and
it turns "air-gapped" from an exaggeration into a statement that is
actually true while still allowing encrypted backups to leave.

**5. Security groups reference roles, not CIDRs.** A rule that says "the
app SG may reach the data SG on 5432" survives subnet reshuffles and
autoscaling. CIDR-based rules rot the first time someone renumbers.

**6. NACLs as a coarse backstop.** NACLs are stateless, so return traffic
forces ephemeral-port allowances that partially cancel their precision.
Their real job here is catching a misconfigured SG before it becomes an
incident, plus an explicit deny for anything unassociated. The SG layer
carries the fine-grained intent.

**7. One customer managed key for the whole audit archive.** Rotation on,
deletion window 30 days, and a key policy where services can only encrypt
on behalf of this account while decryption for forensics is only possible
via S3. One key means one audit story for the whole evidence chain.

**8. Object lock in governance mode for 30 days.** Governance (not
compliance) so the account root retains a break-glass path; even so, no
regular principal can overwrite or delete a log inside the window.
Versioning is implied by the lock, which also protects against overwrite
attacks on prior versions.

**9. Flow logs to S3 parquet at 1-minute aggregation.** Parquet keeps
Athena scan costs low; one-minute aggregation keeps forensic timelines
tight without the per-record cost of CloudWatch delivery for the bulk
copy. CloudWatch still carries the trail itself for real-time alarms.

**10. Default security group and default NACL are locked.** Anything
launched without an explicit firewall config starts dark instead of open.
Accidents should fail closed.

**11. Bucket owner preferred on the log vault.** The classic AWS log
delivery policies (CloudTrail, flow logs) expect the
`bucket-owner-full-control` ACL header; preferred ownership keeps those
battle-tested policies working while staying inside the account.

## State and lifecycle

The state file contains account IDs and resource identifiers, so it
belongs in a locked S3 backend with DynamoDB locking (template in
`backend.tf.example`, setup in the runbook). The stack is fully
additive and fully destructible: `terraform destroy` removes everything,
including the log vault (which holds only its own demo logs). In a real
estate you would keep the vault in a separate account and stack - the
roadmap notes this.
