"""Render findings as text, JSON, or SARIF 2.1.0."""

from __future__ import annotations

import json

from . import __version__
from .diff import RULES, SEVERITY_ORDER

INFO_URI = "https://github.com/garag0l/trust-policy-watch"

_SARIF_SECURITY_SEVERITY = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.5",
    "low": "3.0",
    "info": "0.0",
}

_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

_COLORS = {
    "critical": "\033[1;31m",
    "high": "\033[31m",
    "medium": "\033[33m",
    "low": "\033[36m",
    "info": "\033[90m",
}
_RESET = "\033[0m"


def summarize(findings) -> dict:
    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    counts["total"] = len(findings)
    return counts


def render_text(findings, use_color: bool = True) -> str:
    if not findings:
        return "No trust-policy drift detected."

    lines = []
    for f in findings:
        tag = f.severity.upper()
        if use_color:
            tag = f"{_COLORS.get(f.severity, '')}{tag}{_RESET}"
        lines.append(f"[{tag}] {f.rule_id} {f.role}: {f.title}")
        lines.append(f"    {f.detail}")
        lines.append(f"    fix: {f.remediation}")
        lines.append("")

    counts = summarize(findings)
    parts = [f"{counts[s]} {s}" for s in ("critical", "high", "medium", "low", "info") if counts.get(s)]
    lines.append(f"{counts['total']} finding(s): " + (", ".join(parts) if parts else "none"))
    return "\n".join(lines)


def render_json(findings) -> str:
    payload = {
        "tool": "trust-policy-watch",
        "version": __version__,
        "summary": summarize(findings),
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def render_sarif(findings) -> str:
    # Worst severity seen per rule drives security-severity for code scanning.
    worst = {}
    for f in findings:
        if SEVERITY_ORDER.get(f.severity, 0) > SEVERITY_ORDER.get(worst.get(f.rule_id, "info"), 0):
            worst[f.rule_id] = f.severity

    rules = []
    for rule_id, (slug, short) in RULES.items():
        rules.append(
            {
                "id": rule_id,
                "name": slug,
                "shortDescription": {"text": short},
                "helpUri": f"{INFO_URI}#checks",
                "properties": {
                    "tags": ["security", "aws", "iam", "trust-policy"],
                    "security-severity": _SARIF_SECURITY_SEVERITY[worst.get(rule_id, "medium")],
                },
            }
        )

    results = []
    for f in findings:
        uri = (f.source or "iam").replace("\\", "/")
        message = f"{f.title} | role: {f.role} | {f.detail} | fix: {f.remediation}"
        results.append(
            {
                "ruleId": f.rule_id,
                "level": _SARIF_LEVEL.get(f.severity, "warning"),
                "message": {"text": message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri},
                            "region": {"startLine": 1},
                        },
                        "logicalLocations": [{"fullyQualifiedName": f.role, "kind": "resource"}],
                    }
                ],
                "partialFingerprints": {
                    "tpw/v1": f"{f.rule_id}:{f.role}:{f.properties.get('account', '')}:{f.title}"
                },
                "properties": {"severity": f.severity, **f.properties},
            }
        )

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "trust-policy-watch",
                        "version": __version__,
                        "informationUri": INFO_URI,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def render(findings, fmt: str, use_color: bool = True) -> str:
    if fmt == "json":
        return render_json(findings)
    if fmt == "sarif":
        return render_sarif(findings)
    return render_text(findings, use_color=use_color)
