# Threat model

## Scope

What this baseline protects: the network segmentation of a small AWS
estate, and the audit record of everything that happened inside it.

What it does not protect: the workloads themselves (that is the host and
application layer of the portfolio), the data at rest in databases (the
data tier's job alongside backup-vault), and things at the edge of the
account like DNS or IAM users - noted honestly at the bottom.

## Assets, in attack-value order

| Asset | Why an attacker wants it |
|---|---|
| Data tier | The crown jewels: customer data, credentials, anything a ransomware gang can double-extort with |
| Audit record | Proof of what happened, and the only way to scope a breach; attackers delete it first |
| KMS key | Turns the vault into unreadable noise if abused, or an obstacle if withheld from the attacker |
| App tier | Pivot point toward the data tier, and a source of egress traffic to disguise |
| NAT EIPs | A known-good IP for blending in |

## Trust boundaries

- Internet -> public tier: one protocol, one port, terminated at the ALB.
- Public -> app, app -> data: SG references only; no CIDR-based trust anywhere in the chain.
- App/data -> internet: mediated by NAT (app) or nonexistent (data).
- Everything -> S3 vault: same-account writes only, TLS enforced, KMS under the hood.
- CI -> deploy: scanners run before any plan exists; a red pipeline stops the misconfiguration, not the incident response.

## STRIDE per component

| Component | Threat | Control in this baseline |
|---|---|---|
| Edge (ALB SG) | Spoofing / DoS from the internet | Single 443 ingress, TLS terminated at the ALB, WAF is roadmap |
| App tier | Elevation by lateral movement | SG chain is referential; NACL backstop on every subnet |
| Data tier | Remote exploitation | Empty route table: no inbound path exists, period |
| Data tier | Exfiltration | One egress rule (S3 prefix list); endpoint policy blocks cross-account S3 |
| Log vault | Insider deletion | Object lock 30d, versioning, BPA, TLS deny, same-account writes |
| Log vault | Tampering in transit | CloudTrail log file validation; SSE-KMS under a scoped CMK |
| KMS | Key abuse | Service principals constrained by SourceAccount; decrypt only via S3 |
| Alarms | Silent compromise | Root usage, unauthorized calls, StopLogging/DeleteTrail all page SNS |
| CI gate | Misconfiguration ships | Checkov + tfsec blocking on every push; skips require inline justifications |

## Attack scenarios this stack is built against

**1. Ransomware lands on an app host, tries to spread.** The host can
talk to the data tier on exactly one port (5432, app-SG-members only)
and to the internet on 443 via NAT. SMB, RDP and everything else dies at
the NACL and SG layers simultaneously. Lateral movement attempts show up
in flow logs as REJECT records; the first thing an investigator greps.

**2. The same host tries to ship stolen data out.** Egress is 443 to
arbitrary destinations (that is what patching requires) - so detection
carries the weight here: flow-log byte counters in Athena flag unusual
outbound volume, and the runbook's exfiltration query is designed for
exactly this morning. The data tier cannot join this channel at all; it
has no NAT route, only the S3 endpoint, which the endpoint policy pins
to this account.

**3. Attacker with stolen app-tier credentials goes for the vault.**
Cross-account S3 access through the endpoint is denied by policy. Even
with same-account credentials, objects in the vault are object-locked;
deletion attempts fail, and every attempt is itself a CloudTrail event.

**4. Insider tries to switch the audit off.** `StopLogging`,
`DeleteTrail` and `UpdateTrail` trip a metric-filter alarm to SNS within
minutes. File-level tampering fails log validation. Bucket-level
tampering fails the object lock and the bucket policy. The alarm itself
publishes through a topic whose policy is source-account scoped.

**5. Someone "just makes the database publicly reachable" to debug.**
The failure mode does not exist: there is no route between a public
path and the data tier, the default SG/NACL deny-all catches anything
launched outside the explicit groups, and Checkov + tfsec would flag
the attempt in the pipeline long before apply.

**6. A compromised CI or developer machine pushes a weakened SG rule.**
The change has to survive `terraform fmt`/`validate`/tflint, then two
security scanners with blocking severities, and any skip it needs shows
up as a diff line with a written justification next to it. Reviewing the
diff means reviewing the security posture, by construction.

## Control mapping (CIS AWS Foundations Benchmark v3.0, approximate)

| This baseline | CIS section |
|---|---|
| S3 BPA on both buckets, TLS-only policy | 2.1.5, 2.1.x |
| Multi-region trail, validation, KMS | 2.2.1, 2.2.2, 2.3.x |
| Flow logs on the VPC | 3.9 (v1.5 numbering, "VPC flow logs enabled") |
| Root usage / unauthorized API / trail-change alarms | 4.1-4.4 family |
| CMK with rotation | 2.8 family |
| Default SG locked | 5.3 family |

Section numbers shift between CIS editions; the mapping is about intent,
and the scanners re-verify the specifics on every push.

## What this baseline does NOT cover (yet)

- **WAF / DDoS on the ALB** - meaningful only once a workload module exists; roadmap.
- **GuardDuty / Security Hub** - managed threat detection feeding the same SNS topic; roadmap.
- **IMDSv2 enforcement and instance hardening** - host-layer, deliberately out of network scope; see linux-hardening for the instance side.
- **Cross-account log archive** - a real estate keeps the vault in a separate audit account; the object lock here is the single-account approximation, the roadmap notes the account split.
- **RDS / database configuration hardening** - the data tier provides the network cell; hardening the database inside it is a workload concern.
