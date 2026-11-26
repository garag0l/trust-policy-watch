"""Live, read-only collection of trust policies via boto3.

boto3 is imported lazily and only here, so the offline/GAAD path has zero
runtime dependencies. This module only ever calls read operations
(``sts:GetCallerIdentity``, ``iam:ListRoles``); it never modifies anything.
"""

from __future__ import annotations

import json
import urllib.parse


def _decode_doc(doc):
    """boto3 usually returns AssumeRolePolicyDocument already decoded to a dict,
    but tolerate the URL-encoded string form as well."""
    if doc is None:
        return {}
    if isinstance(doc, dict):
        return doc
    if isinstance(doc, str):
        return json.loads(urllib.parse.unquote(doc))
    return {}


def collect_roles(profile: str | None = None):
    """Collect every role's trust policy from the live account.

    Returns ``(account, roles)`` where ``roles`` is a list of
    ``{role_name, arn, trust}`` records. Requires the ``live`` extra
    (``pip install trust-policy-watch[live]``).
    """
    try:
        import boto3  # noqa: PLC0415 (lazy import by design)
    except ImportError as exc:  # pragma: no cover - exercised only without boto3
        raise SystemExit(
            "boto3 is required for --live. Install it with: pip install 'trust-policy-watch[live]'"
        ) from exc

    session = boto3.Session(profile_name=profile) if profile else boto3.Session()

    account = None
    try:
        account = session.client("sts").get_caller_identity().get("Account")
    except Exception:  # pragma: no cover - sts may be denied; account stays None
        account = None

    iam = session.client("iam")
    roles = []
    paginator = iam.get_paginator("list_roles")
    for page in paginator.paginate():
        for role in page.get("Roles", []):
            roles.append(
                {
                    "role_name": role["RoleName"],
                    "arn": role["Arn"],
                    "trust": _decode_doc(role.get("AssumeRolePolicyDocument")),
                }
            )
    return account, roles
