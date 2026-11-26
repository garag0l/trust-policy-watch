"""Compare a baseline snapshot against current trust policies and flag drift.

The signals this surfaces map directly onto the ``iam:UpdateAssumeRolePolicy``
persistence technique: an attacker (or a mistake) adds a new principal / account
/ wildcard to a role's trust policy, or drops a protective Condition such as
ExternalId or MFA.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .trust import account_id_of

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# rule_id -> (slug, short description) for reporting / SARIF.
RULES = {
    "TPW-001": ("wildcard-public", "Wildcard or public principal added to a trust policy"),
    "TPW-002": ("new-external-account", "New external/cross-account principal added to a trust policy"),
    "TPW-003": ("principal-change", "Trust policy principal changed"),
    "TPW-004": ("dropped-identity-condition", "Protective identity Condition (ExternalId/MFA) removed"),
    "TPW-005": ("dropped-source-condition", "Protective source Condition (SourceArn/SourceAccount) removed"),
    "TPW-006": ("role-inventory-change", "Role added or removed since baseline"),
}

_EMPTY_NORMALIZED = {
    "aws_principals": [],
    "service_principals": [],
    "federated_principals": [],
    "wildcard": False,
    "accounts": [],
    "condition_keys": [],
    "protections": [],
    "statements": [],
}


@dataclass
class Finding:
    rule_id: str
    rule_name: str
    role: str
    severity: str
    title: str
    detail: str
    remediation: str
    source: str = ""
    properties: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "role": self.role,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "remediation": self.remediation,
            "source": self.source,
            "properties": self.properties,
        }


def meets(severity: str, threshold: str) -> bool:
    """True if ``severity`` is at or above ``threshold``."""
    return SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER.get(threshold, 0)


def _external_accounts(roles: dict, own_account) -> set:
    """Every external account already trusted somewhere in the baseline."""
    accts = set()
    for rec in roles.values():
        for principal in rec.get("normalized", {}).get("aws_principals", []):
            acct = account_id_of(principal)
            if acct and acct != own_account:
                accts.add(acct)
    return accts


def _diff_role(name, before, after, snapshot_account, baseline_external, arn, source, is_new=False):
    findings = []
    role_account = account_id_of(arn) or snapshot_account

    # A wildcard principal that was not there before: anyone can assume the role.
    if after["wildcard"] and not before["wildcard"]:
        findings.append(
            Finding(
                "TPW-001", RULES["TPW-001"][0], name, "critical",
                "Public (wildcard) principal added to trust policy",
                'The trust policy now allows principal "*" — the role is assumable by any AWS account.',
                'Remove the "*" principal and scope trust to specific account IDs or role ARNs.',
                source, {"wildcard": True},
            )
        )

    # New AWS principals.
    added_aws = sorted(set(after["aws_principals"]) - set(before["aws_principals"]))
    for principal in added_aws:
        acct = account_id_of(principal)
        if acct and role_account and acct != role_account:
            if acct in baseline_external:
                sev, title = "high", "New cross-account principal added (account already trusted elsewhere)"
            else:
                sev, title = "critical", "New untrusted external account added to trust policy"
            findings.append(
                Finding(
                    "TPW-002", RULES["TPW-002"][0], name, sev, title,
                    f"Principal {principal} (external account {acct}) can now assume this role.",
                    "Confirm this cross-account trust is intended; otherwise remove the principal.",
                    source, {"principal": principal, "account": acct},
                )
            )
        else:
            findings.append(
                Finding(
                    "TPW-003", RULES["TPW-003"][0], name, "medium",
                    "New same-account principal added to trust policy",
                    f"Principal {principal} was added to the trust policy.",
                    "Verify the new principal is expected.",
                    source, {"principal": principal},
                )
            )

    # New federated principals (SAML/OIDC providers).
    for principal in sorted(set(after["federated_principals"]) - set(before["federated_principals"])):
        findings.append(
            Finding(
                "TPW-003", RULES["TPW-003"][0], name, "medium",
                "New federated principal added to trust policy",
                f"Federated principal {principal} was added to the trust policy.",
                "Verify the federation change is expected.",
                source, {"federated": principal},
            )
        )

    # Dropped protective conditions.
    dropped = set(before["protections"]) - set(after["protections"])
    for protection in sorted(dropped):
        if protection in ("ExternalId", "MFA"):
            findings.append(
                Finding(
                    "TPW-004", RULES["TPW-004"][0], name, "high",
                    f"Protective Condition {protection} removed from trust policy",
                    f"The {protection} condition that guarded assumption of this role was removed.",
                    f"Restore the {protection} condition to prevent unauthorized assumption.",
                    source, {"protection": protection},
                )
            )
        else:
            findings.append(
                Finding(
                    "TPW-005", RULES["TPW-005"][0], name, "medium",
                    f"Protective Condition {protection} removed from trust policy",
                    f"The {protection} confused-deputy protection was removed from this role.",
                    f"Restore the {protection} condition.",
                    source, {"protection": protection},
                )
            )

    if is_new:
        findings.append(
            Finding(
                "TPW-006", RULES["TPW-006"][0], name, "info",
                "New role observed since baseline",
                f"Role {name} did not exist in the baseline.",
                "Confirm the new role and its trust policy are expected.",
                source, {"change": "added"},
            )
        )
    return findings


def diff(baseline: dict, current: dict):
    """Return a severity-sorted list of :class:`Finding` for baseline -> current."""
    b_roles = baseline.get("roles", {})
    c_roles = current.get("roles", {})
    snapshot_account = current.get("account") or baseline.get("account")
    baseline_external = _external_accounts(b_roles, baseline.get("account"))
    source = current.get("source", "")

    findings = []

    # New roles: diff against an empty baseline so risky trust is still flagged.
    for name in sorted(set(c_roles) - set(b_roles)):
        rec = c_roles[name]
        findings += _diff_role(
            name, _EMPTY_NORMALIZED, rec["normalized"], snapshot_account,
            baseline_external, rec.get("arn", ""), source, is_new=True,
        )

    # Deleted roles.
    for name in sorted(set(b_roles) - set(c_roles)):
        rec = b_roles[name]
        findings.append(
            Finding(
                "TPW-006", RULES["TPW-006"][0], name, "info",
                "Role deleted since baseline",
                f"Role {name} existed in the baseline but is gone now.",
                "Confirm the role removal was intended.",
                source, {"change": "deleted"},
            )
        )

    # Changed roles.
    for name in sorted(set(b_roles) & set(c_roles)):
        before, after = b_roles[name], c_roles[name]
        if before.get("hash") == after.get("hash"):
            continue
        findings += _diff_role(
            name, before["normalized"], after["normalized"], snapshot_account,
            baseline_external, after.get("arn", ""), source,
        )

    findings.sort(key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), f.rule_id, f.role))
    return findings
