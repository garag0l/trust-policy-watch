# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-26

### Added
- `snapshot` command: capture every IAM role's trust policy
  (`AssumeRolePolicyDocument`) into a baseline JSON, from the live account
  (`--live`, boto3, read-only, paginated) or offline from a
  `get-account-authorization-details` file (`--gaad`).
- `diff` command: compare current trust policies against a baseline and flag
  added principals, new cross-account/public trust, and dropped protective
  conditions (ExternalId, MFA, SourceArn, SourceAccount), plus new/deleted
  roles. Severity-ranked findings with `--fail-on` exit codes.
- Output formats: `text`, `json`, and SARIF 2.1.0.
- `boto3` is an optional extra (`[live]`); the offline/GAAD path has zero
  runtime dependencies.
