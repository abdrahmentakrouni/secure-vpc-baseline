# secure-vpc-baseline

[![CI](https://github.com/abdrahmentakrouni/secure-vpc-baseline/actions/workflows/ci.yml/badge.svg)](https://github.com/abdrahmentakrouni/secure-vpc-baseline/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/abdrahmentakrouni/secure-vpc-baseline)](https://github.com/abdrahmentakrouni/secure-vpc-baseline/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Terraform](https://img.shields.io/badge/Terraform-%3E%3D%201.5-7B42BC)](https://www.terraform.io)
[![AWS](https://img.shields.io/badge/AWS-VPC%20%7C%20KMS%20%7C%20CloudTrail-FF9900)](https://aws.amazon.com)
[![Scanned by Checkov + tfsec](https://img.shields.io/badge/scanned%20by-checkov%20%2B%20tfsec-2EC4B6)](.github/workflows/ci.yml)

A secure AWS network built entirely as code, with a CI pipeline that refuses
to merge misconfigurations. Three isolated tiers, a dual firewall that runs on
least privilege, and a forensic audit archive that even an account admin
cannot rewrite or delete.

This is the network foundation of a bigger story about resilience:

| Layer | Project | Question it answers |
|---|---|---|
| Host | [linux-hardening](https://github.com/abdrahmentakrouni/linux-hardening) | Is the server itself safe? |
| Application | [secure-nextcloud](https://github.com/abdrahmentakrouni/secure-nextcloud) | Is the data-in-use safe? |
| Data | [backup-vault](https://github.com/abdrahmentakrouni/backup-vault) | Can we recover after a disaster? |
| **Network** | **secure-vpc-baseline** | **Can an attacker even move, and will we know?** |

## The design in one picture

```
                         ┌───────────────────── VPC  10.40.0.0/16 ─────────────────────┐
                         │                                                             │
  Internet ──HTTPS 443──▶│──▶ Internet Gateway                                         │
                         │          │                                                  │
                         │   ┌───────▼──── public tier (one /20 per AZ) ───────┐        │
                         │   │   ALB terminates TLS, forwards on 8080          │        │
                         │   │   NAT gateways live here (one per AZ)           │        │
                         │   └───────┬───────────────────────▲─────────────────┘        │
                         │           │ 8080                  │                          │
                         │           ▼ (SG reference)      │ outbound only, via NAT   │
                         │   ┌───────┴──── app tier ───────┴─────────────────┐        │
                         │   │   application servers                         │        │
                         │   │   managed through SSM endpoints, no bastion   │        │
                         │   └───────┬───────────────────────▲─────────────────┘        │
                         │           │ 5432                  │ TLS to S3 endpoint       │
                         │           ▼ (SG reference)      │ (encrypted backups)      │
                         │   ┌───────┴──── data tier ──────┴─────────────────┐        │
                         │   │   databases                                   │        │
                         │   │   route table is EMPTY: no internet in or out │        │
                         │   └───────────────────────────────────────────────┘        │
                         └─────────────────────────────────────────────────────────────┘
                                             │
                                             ▼  every CloudTrail event and every flow log
                         ┌─────────────────── S3 log vault ──────────────────────────────┐
                         │   versioned + KMS (customer managed key, rotated)             │
                         │   object-locked 30 days: nobody rewrites the evidence         │
                         │   TLS enforced, same-account writes only                      │
                         └───────────────────────────────────────────────────────────────┘
```

## Five walls, one baseline

| Wall | Control | What it stops |
|---|---|---|
| Tier isolation | Public / app / data subnets, data tier has an empty route table | A database that is reachable "from the internet by accident" cannot exist here |
| Dual firewall | Security groups reference each other by role; NACLs backstop every subnet | Lateral movement with wrong ports, misconfigured SGs, unexpected listeners |
| Egress discipline | NAT only, HTTPS only, S3 gateway endpoint for the data tier | A compromised host calling home or shipping data to arbitrary destinations |
| Full audit | Multi-region CloudTrail + VPC flow logs (1-min, parquet) into one KMS vault | "We don't know what happened" after an incident |
| Evidence integrity | Object lock + versioning + log file validation + tamper alarms | Insider or attacker deleting the trail: `StopLogging`, `DeleteTrail` and root usage all page SNS |

Every knob is a variable, every default is the secure one, and the whole
thing can be torn down with one command when the demo is over.

## Quick start

Prerequisites: Terraform >= 1.5, AWS CLI v2, credentials with VPC/S3/KMS/CloudTrail permissions.

```bash
git clone https://github.com/abdrahmentakrouni/secure-vpc-baseline.git
cd secure-vpc-baseline

cp terraform.tfvars.example terraform.tfvars   # then edit values

terraform init
terraform plan      # read it, every line
terraform apply     # about 10 minutes, NAT gateways are the slow part
```

Remote state is strongly recommended (the state file carries account IDs).
`backend.tf.example` shows the S3 backend, one-time setup is in the
[runbook](docs/runbook.md).

## The CI security gate

Every push and pull request runs three jobs, and a red one blocks the merge:

1. **Format, validate, lint** - `terraform fmt -check`, `terraform validate`,
   `tflint` with the recommended rule set.
2. **Checkov** - 170+ policies for Terraform misconfigurations. Runs with
   `soft_fail: false`, so a HIGH finding fails the build.
3. **tfsec** - a second scanner from the Trivy family, catching what the
   first one misses. Also blocking.

Twelve checks are skipped, each with a written justification next to the
resource (for example: the terminal access-log sink cannot log itself
recursively). Skipping with a reason is the professional pattern, silent
suppression is not.

## Forensics after a breach

The vault is designed for the morning after: flow logs land as parquet in
hour-partitioned prefixes, so an Athena query over them costs cents. The
[runbook](docs/runbook.md) ships the table DDL and the first queries to run:
top talkers, denied flows inside the data tier, and internal hosts with
suspicious outbound volume. CloudTrail answers "who did what with which API
call", flow logs answer "who talked to whom, when, and how much".

## What it costs

Approximate eu-west-3 prices, defaults (2 AZs, NAT per AZ, SSM endpoints on):

| Item | Monthly |
|---|---|
| 2 NAT gateways | ~ $66 |
| 6 interface endpoints (SSM x3 per AZ) | ~ $44 |
| KMS key + API calls | ~ $2 |
| S3 vault, CloudWatch, SNS, CloudTrail | ~ $3 |

Dev mode (`single_nat_gateway = true`, `enable_ssm_endpoints = false`) lands
around $35. Always `terraform destroy` when done with a playground.

## Repository layout

```
├── main.tf              VPC, three tiers, NAT, route tables
├── security.tf          Security groups + rules, NACLs, default deny-all pair
├── endpoints.tf         S3 gateway endpoint, SSM interface endpoints
├── kms.tf               Customer managed key, rotation, scoped key policy
├── logging.tf           Log vault buckets, CloudTrail, flow logs, alarms, SNS
├── variables.tf         Every knob, validated
├── backend.tf.example   Remote state template
├── docs/
│   ├── architecture.md  CIDR math, traffic flows, design decisions
│   ├── threat-model.md  STRIDE table, attack scenarios, control mapping
│   └── runbook.md       Deploy, verify, investigate, destroy
└── .github/workflows/ci.yml   the gate itself
```

## Docs

- [Architecture](docs/architecture.md) - why every wall exists and what it cost in complexity
- [Threat model](docs/threat-model.md) - the scenarios this baseline is built against
- [Runbook](docs/runbook.md) - from `terraform init` to querying flow logs in Athena

## Roadmap

- GuardDuty + Security Hub integration feeding the same SNS topic
- S3 cross-region replication of the log vault for enterprise estates
- EKS / RDS workload modules that consume the app and data tiers
- Web ACL on the ALB once a workload module exists

## License

MIT - see [LICENSE](LICENSE).
