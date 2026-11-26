"""Mocked-AWS tests with moto. No real AWS credentials are ever used."""

import json

import pytest

moto = pytest.importorskip("moto")
from moto import mock_aws  # noqa: E402

from trust_policy_watch.diff import diff  # noqa: E402
from trust_policy_watch.live import collect_roles  # noqa: E402
from trust_policy_watch.snapshot import build_snapshot  # noqa: E402

# Obvious fake account ids only.
INTERNAL = "111111111111"
EXTERNAL = "222222222222"
ATTACKER = "999999999999"

BASE_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{INTERNAL}:root"},
            "Action": "sts:AssumeRole",
            "Condition": {"StringEquals": {"sts:ExternalId": "secret-abc"}},
        }
    ],
}


def _snapshot():
    account, roles = collect_roles()
    return build_snapshot(account, roles, "live")


def _attacker_trust(extra_account, with_external_id=True, wildcard=False):
    principal = {"AWS": [f"arn:aws:iam::{INTERNAL}:root"]}
    if wildcard:
        principal = "*"
    elif extra_account:
        principal["AWS"].append(f"arn:aws:iam::{extra_account}:root")
    stmt = {"Effect": "Allow", "Principal": principal, "Action": "sts:AssumeRole"}
    if with_external_id:
        stmt["Condition"] = {"StringEquals": {"sts:ExternalId": "secret-abc"}}
    return {"Version": "2012-10-17", "Statement": [stmt]}


@mock_aws
def test_live_collect_sees_role():
    import boto3

    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_role(RoleName="r1", AssumeRolePolicyDocument=json.dumps(BASE_TRUST))

    account, roles = collect_roles()
    assert any(r["role_name"] == "r1" for r in roles)
    rec = next(r for r in roles if r["role_name"] == "r1")
    # boto3 returns the document decoded; ExternalId condition must be visible.
    assert "Statement" in rec["trust"]


@mock_aws
def test_update_adds_external_account_flagged_critical():
    import boto3

    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_role(RoleName="r1", AssumeRolePolicyDocument=json.dumps(BASE_TRUST))
    baseline = _snapshot()

    # Simulate the UpdateAssumeRolePolicy persistence technique.
    iam.update_assume_role_policy(
        RoleName="r1",
        PolicyDocument=json.dumps(_attacker_trust(ATTACKER, with_external_id=False)),
    )
    current = _snapshot()

    findings = diff(baseline, current)
    external = [f for f in findings if f.rule_id == "TPW-002"]
    assert len(external) == 1
    assert external[0].severity == "critical"
    assert external[0].properties["account"] == ATTACKER

    # ExternalId was also dropped -> high finding.
    dropped = [f for f in findings if f.rule_id == "TPW-004"]
    assert dropped and dropped[0].severity == "high"


@mock_aws
def test_update_adds_wildcard_flagged_critical():
    import boto3

    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_role(RoleName="r1", AssumeRolePolicyDocument=json.dumps(BASE_TRUST))
    baseline = _snapshot()

    iam.update_assume_role_policy(RoleName="r1", PolicyDocument=json.dumps(_attacker_trust(None, wildcard=True)))
    current = _snapshot()

    findings = diff(baseline, current)
    wild = [f for f in findings if f.rule_id == "TPW-001"]
    assert len(wild) == 1
    assert wild[0].severity == "critical"
    assert "public" in wild[0].title.lower() or "wildcard" in wild[0].title.lower()


@mock_aws
def test_dropping_external_id_only_is_high():
    import boto3

    iam = boto3.client("iam", region_name="us-east-1")
    # Start trusting an external account WITH an ExternalId guard.
    start = _attacker_trust(EXTERNAL, with_external_id=True)
    iam.create_role(RoleName="r1", AssumeRolePolicyDocument=json.dumps(start))
    baseline = _snapshot()

    # Drop only the ExternalId, keep principals.
    iam.update_assume_role_policy(RoleName="r1", PolicyDocument=json.dumps(_attacker_trust(EXTERNAL, with_external_id=False)))
    current = _snapshot()

    findings = diff(baseline, current)
    assert [f for f in findings if f.rule_id == "TPW-002"] == []  # no new account
    dropped = [f for f in findings if f.rule_id == "TPW-004"]
    assert len(dropped) == 1
    assert dropped[0].severity == "high"


@mock_aws
def test_new_role_since_baseline_is_info():
    import boto3

    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_role(RoleName="r1", AssumeRolePolicyDocument=json.dumps(BASE_TRUST))
    baseline = _snapshot()

    iam.create_role(RoleName="r2", AssumeRolePolicyDocument=json.dumps(BASE_TRUST))
    current = _snapshot()

    findings = diff(baseline, current)
    new_role = [f for f in findings if f.rule_id == "TPW-006" and f.role == "r2"]
    assert new_role and new_role[0].severity == "info"


@mock_aws
def test_deleted_role_since_baseline_is_info():
    import boto3

    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_role(RoleName="r1", AssumeRolePolicyDocument=json.dumps(BASE_TRUST))
    iam.create_role(RoleName="r2", AssumeRolePolicyDocument=json.dumps(BASE_TRUST))
    baseline = _snapshot()

    iam.delete_role(RoleName="r2")
    current = _snapshot()

    findings = diff(baseline, current)
    deleted = [f for f in findings if f.rule_id == "TPW-006" and f.role == "r2"]
    assert deleted and deleted[0].severity == "info"
    assert "deleted" in deleted[0].properties.get("change", "")
