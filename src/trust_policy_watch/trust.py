"""Parse and normalize an IAM role trust policy (AssumeRolePolicyDocument).

A trust policy grants ``sts:AssumeRole`` to one or more principals, optionally
guarded by a Condition (ExternalId, MFA, SourceArn, SourceAccount). This module
turns the raw document into a stable, comparable, hashable shape and extracts
the facts drift detection cares about: which accounts/principals are trusted,
whether trust is public (``*``), and which protective conditions are present.
"""

from __future__ import annotations

import hashlib
import json
import re

# Matches the 12-digit account id in an IAM/STS ARN, e.g. arn:aws:iam::123456789012:root
_ARN_ACCOUNT_RE = re.compile(r"arn:aws[a-z-]*:[^:]*:[^:]*:(\d{12}):")
_BARE_ACCOUNT_RE = re.compile(r"^\d{12}$")

# Lower-cased condition keys that represent protective guards on a trust policy.
_PROTECTION_KEYS = {
    "sts:externalid": "ExternalId",
    "aws:multifactorauthpresent": "MFA",
    "aws:sourcearn": "SourceArn",
    "aws:sourceaccount": "SourceAccount",
}


def _as_list(value):
    """Coerce a scalar-or-list policy field into a list."""
    if value is None:
        return []
    if isinstance(value, list):
        return list(value)
    return [value]


def account_id_of(principal_value: str):
    """Return the 12-digit AWS account id for a principal/ARN string, or None.

    Handles ``arn:aws:iam::123456789012:root``, ``...:user/x``, and a bare
    account id. Returns None for ``*`` or service/federated principals.
    """
    if not isinstance(principal_value, str) or principal_value == "*":
        return None
    m = _ARN_ACCOUNT_RE.search(principal_value)
    if m:
        return m.group(1)
    if _BARE_ACCOUNT_RE.match(principal_value):
        return principal_value
    return None


def _condition_keys(condition) -> set:
    """Collect every condition key present, across all operators."""
    keys = set()
    if isinstance(condition, dict):
        for _operator, kv in condition.items():
            if isinstance(kv, dict):
                keys.update(kv.keys())
    return keys


def protections(condition_keys) -> set:
    """Map raw condition keys to the set of protective guards they represent."""
    found = set()
    for key in condition_keys:
        name = _PROTECTION_KEYS.get(str(key).lower())
        if name:
            found.add(name)
    return found


def normalize_statement(statement: dict) -> dict:
    """Normalize a single trust-policy statement into comparable fields."""
    principal = statement.get("Principal", {})
    aws, services, federated = [], [], []
    wildcard = False

    if principal == "*":
        wildcard = True
    elif isinstance(principal, dict):
        for key, raw in principal.items():
            for value in _as_list(raw):
                if value == "*":
                    wildcard = True
                if key == "AWS":
                    aws.append(value)
                elif key == "Service":
                    services.append(value)
                elif key == "Federated":
                    federated.append(value)

    keys = _condition_keys(statement.get("Condition", {}))
    return {
        "effect": statement.get("Effect", "Allow"),
        "actions": sorted({a for a in _as_list(statement.get("Action"))}),
        "aws_principals": sorted(set(aws)),
        "service_principals": sorted(set(services)),
        "federated_principals": sorted(set(federated)),
        "wildcard": wildcard,
        "condition_keys": sorted(keys),
    }


def normalize_trust(document) -> dict:
    """Normalize a whole trust-policy document into a role-level summary."""
    if not isinstance(document, dict):
        document = {}
    statements = [normalize_statement(s) for s in _as_list(document.get("Statement")) if isinstance(s, dict)]

    aws_principals = sorted({p for s in statements for p in s["aws_principals"]})
    service_principals = sorted({p for s in statements for p in s["service_principals"]})
    federated_principals = sorted({p for s in statements for p in s["federated_principals"]})
    wildcard = any(s["wildcard"] for s in statements)
    condition_keys = sorted({k for s in statements for k in s["condition_keys"]})
    accounts = sorted({a for p in aws_principals for a in (account_id_of(p),) if a})

    return {
        "aws_principals": aws_principals,
        "service_principals": service_principals,
        "federated_principals": federated_principals,
        "wildcard": wildcard,
        "accounts": accounts,
        "condition_keys": condition_keys,
        "protections": sorted(protections(condition_keys)),
        "statements": statements,
    }


def trust_hash(normalized: dict) -> str:
    """Stable SHA-256 of a normalized trust policy, for fast change detection."""
    blob = json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()
