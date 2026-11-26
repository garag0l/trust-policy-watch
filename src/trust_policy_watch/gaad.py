"""Offline parsing of ``aws iam get-account-authorization-details`` (GAAD) JSON.

This path needs no AWS credentials and no third-party dependencies: it reads a
file you already captured and extracts each role's trust policy.
"""

from __future__ import annotations

import json
import urllib.parse

from .trust import account_id_of


def _decode_doc(doc):
    """GAAD normally embeds the trust policy as a JSON object, but tolerate a
    URL-encoded string too (the raw IAM API wire form)."""
    if doc is None:
        return {}
    if isinstance(doc, dict):
        return doc
    if isinstance(doc, str):
        return json.loads(urllib.parse.unquote(doc))
    return {}


def load_gaad(path: str):
    """Read a GAAD file and return ``(account, roles)``.

    ``account`` is inferred as the most common account id across role ARNs.
    ``roles`` is a list of ``{role_name, arn, trust}`` records.
    """
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)

    roles = []
    account_counts: dict[str, int] = {}
    for entry in data.get("RoleDetailList", []):
        arn = entry.get("Arn", "")
        roles.append(
            {
                "role_name": entry.get("RoleName", ""),
                "arn": arn,
                "trust": _decode_doc(entry.get("AssumeRolePolicyDocument")),
            }
        )
        acct = account_id_of(arn)
        if acct:
            account_counts[acct] = account_counts.get(acct, 0) + 1

    account = max(account_counts, key=account_counts.get) if account_counts else None
    return account, roles
