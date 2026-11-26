"""Unit tests for trust-policy parsing/normalization."""

from trust_policy_watch.trust import account_id_of, normalize_trust, protections, trust_hash


def test_account_id_of_from_arn():
    assert account_id_of("arn:aws:iam::123456789012:root") == "123456789012"
    assert account_id_of("arn:aws:iam::123456789012:role/thing") == "123456789012"


def test_account_id_of_bare_and_wildcard():
    assert account_id_of("210987654321") == "210987654321"
    assert account_id_of("*") is None
    assert account_id_of("ec2.amazonaws.com") is None


def test_normalize_detects_wildcard_principal():
    doc = {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]}
    norm = normalize_trust(doc)
    assert norm["wildcard"] is True


def test_normalize_detects_wildcard_in_aws_key():
    doc = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}]}
    assert normalize_trust(doc)["wildcard"] is True


def test_normalize_collects_accounts_and_service():
    doc = {
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"},
            {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::222222222222:root"}, "Action": "sts:AssumeRole"},
        ]
    }
    norm = normalize_trust(doc)
    assert norm["accounts"] == ["222222222222"]
    assert norm["service_principals"] == ["ec2.amazonaws.com"]
    assert norm["wildcard"] is False


def test_protections_mapping():
    keys = ["sts:ExternalId", "aws:MultiFactorAuthPresent", "aws:SourceArn", "aws:SourceAccount"]
    assert protections(keys) == {"ExternalId", "MFA", "SourceArn", "SourceAccount"}


def test_normalize_extracts_protections():
    doc = {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::222222222222:root"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"sts:ExternalId": "x"}},
            }
        ]
    }
    assert normalize_trust(doc)["protections"] == ["ExternalId"]


def test_hash_is_stable_and_order_independent():
    a = normalize_trust({"Statement": [{"Principal": {"AWS": ["arn:aws:iam::111111111111:root", "arn:aws:iam::222222222222:root"]}}]})
    b = normalize_trust({"Statement": [{"Principal": {"AWS": ["arn:aws:iam::222222222222:root", "arn:aws:iam::111111111111:root"]}}]})
    assert trust_hash(a) == trust_hash(b)


def test_hash_changes_on_new_principal():
    a = normalize_trust({"Statement": [{"Principal": {"AWS": "arn:aws:iam::111111111111:root"}}]})
    b = normalize_trust({"Statement": [{"Principal": {"AWS": ["arn:aws:iam::111111111111:root", "arn:aws:iam::999999999999:root"]}}]})
    assert trust_hash(a) != trust_hash(b)
