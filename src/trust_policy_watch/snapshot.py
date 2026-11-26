"""Build a baseline snapshot of every role's trust policy."""

from __future__ import annotations

import datetime

from . import __version__
from .trust import normalize_trust, trust_hash

SCHEMA_VERSION = 1


def build_snapshot(account, roles, source: str) -> dict:
    """Turn a list of ``{role_name, arn, trust}`` records into a baseline dict.

    ``roles`` is produced by :mod:`trust_policy_watch.live` or
    :mod:`trust_policy_watch.gaad`. ``account`` is the account the snapshot was
    taken from (used as the "internal" account when detecting cross-account
    trust). ``source`` is a short provenance string such as ``"live"`` or
    ``"gaad:details.json"``.
    """
    out_roles = {}
    for record in roles:
        normalized = normalize_trust(record.get("trust"))
        name = record["role_name"]
        out_roles[name] = {
            "role_name": name,
            "arn": record.get("arn", ""),
            "trust": record.get("trust", {}),
            "normalized": normalized,
            "hash": trust_hash(normalized),
        }

    return {
        "tool": "trust-policy-watch",
        "version": __version__,
        "schema": SCHEMA_VERSION,
        "source": source,
        "account": account,
        "created": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "roles": out_roles,
    }
