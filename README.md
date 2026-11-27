# trust-policy-watch

Detect **drift and persistence in AWS IAM role trust policies** — the
`AssumeRolePolicyDocument` that decides *who may assume a role*.

A well-known attacker persistence technique is calling
**`iam:UpdateAssumeRolePolicy`** to quietly add their own principal, account, or
a `*` wildcard to a role's trust policy, or to drop a protective `Condition`
(ExternalId, MFA, SourceArn, SourceAccount) that previously constrained who
could assume the role. These changes rarely trigger alarms on their own.

`trust-policy-watch` **snapshots** every role's trust policy into a baseline and
**diffs** it over time, surfacing exactly those changes with a severity rank and
machine-readable output (JSON / SARIF).

It is **read-only** and never modifies anything in your account.

> 🌐 **Inspect a single policy in your browser** — [Trust Policy Inspector](https://garag0l.github.io/trust-policy-watch/): paste one role's trust policy and see who can assume it and which protective conditions are missing. No install, no AWS credentials, nothing uploaded.

## Why trust policies

The trust policy is the lock on a role. Monitoring attached *permission*
policies is common; monitoring the trust document — the thing that controls
*who can walk through the door* — is often overlooked, yet it is precisely where
cross-account and persistence backdoors are planted.

## What it flags

Per role, comparing current trust against a baseline:

- **Public / wildcard trust** — a `*` principal added (role assumable by anyone) — *critical*
- **New untrusted external account** — a cross-account principal for an account not previously trusted anywhere — *critical*
- **New cross-account principal** — a new principal for an account already trusted elsewhere — *high*
- **Dropped identity Condition** — `sts:ExternalId` or `aws:MultiFactorAuthPresent` removed — *high*
- **Dropped source Condition** — `aws:SourceArn` / `aws:SourceAccount` removed — *medium*
- **Other principal changes** — new same-account or federated principals — *medium*
- **New / deleted roles** since the baseline — *info*

## Permissions required (read-only)

The AWS-managed **`SecurityAudit`** policy is sufficient. If you prefer a
minimal custom policy, the only actions needed are:

- `iam:ListRoles`
- `iam:GetRole`

The offline mode needs **no AWS access at all** — it reads a file you already
captured with `aws iam get-account-authorization-details`.

## Install

```bash
# offline / GAAD mode only — zero dependencies
pip install trust-policy-watch

# live AWS mode (adds boto3)
pip install "trust-policy-watch[live]"
```

Requires Python 3.9+.

## Usage

### 1. Snapshot a baseline

```bash
# Live account (read-only), optionally a named profile
trust-policy-watch snapshot --live --profile prod -o baseline.json

# Offline, from a captured authorization-details file (no credentials)
aws iam get-account-authorization-details > details.json
trust-policy-watch snapshot --gaad details.json -o baseline.json
```

Commit `baseline.json` to a private repo. That becomes your known-good state.

### 2. Diff later to catch drift

```bash
trust-policy-watch diff --baseline baseline.json --live
```

Example output:

```
[CRITICAL] TPW-002 vendor-integration-role: New untrusted external account added to trust policy
    Principal arn:aws:iam::999999999999:root (external account 999999999999) can now assume this role.
    fix: Confirm this cross-account trust is intended; otherwise remove the principal.

[HIGH] TPW-004 vendor-integration-role: Protective Condition ExternalId removed from trust policy
    The ExternalId condition that guarded assumption of this role was removed.
    fix: Restore the ExternalId condition to prevent unauthorized assumption.

2 finding(s): 1 critical, 1 high
```

### Output formats and exit codes

```bash
trust-policy-watch diff --baseline baseline.json --gaad details.json -f json
trust-policy-watch diff --baseline baseline.json --gaad details.json -f sarif -o trust.sarif
```

- `-f {text,json,sarif}` — output format
- `-o FILE` — write to a file instead of stdout
- `--min-severity {critical,high,medium,low,info}` — only report at or above
- `--fail-on {critical,high,medium,low,info}` — exit non-zero if any finding is at or above this (default: `high`), for CI gating
- `--no-color` — plain text

### SARIF

The `sarif` format emits SARIF 2.1.0 with one rule per finding type and a
`security-severity` on each rule, so results render natively in **GitHub code
scanning** (upload `trust.sarif` via `github/codeql-action/upload-sarif`).

## GitHub Action (optional)

A composite action runs a diff against a committed baseline on every push:

```yaml
- uses: garag0l/trust-policy-watch@v0.1.0
  with:
    baseline: baseline.json
    gaad: details.json      # or set live: 'true' with AWS credentials configured
    fail-on: high
    format: sarif
    output: trust.sarif
```

## Authorized use only

`trust-policy-watch` is a **defensive** tool. Use it **only** on AWS accounts you
own or are explicitly authorized to assess. It performs **read-only** IAM calls
(`iam:ListRoles`, `iam:GetRole`) or reads an offline file; it **never** creates,
updates, or deletes any AWS resource and never modifies a trust policy. Do not
use it to probe accounts you are not authorized to audit.

## License

MIT — see [LICENSE](LICENSE).
