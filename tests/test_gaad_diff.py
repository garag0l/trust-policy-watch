"""Offline GAAD parsing, diff findings, report formats, and fail-on exit codes."""

import json
import os

from trust_policy_watch.cli import main
from trust_policy_watch.diff import diff, meets
from trust_policy_watch.gaad import load_gaad
from trust_policy_watch.report import render_json, render_sarif
from trust_policy_watch.snapshot import build_snapshot

FIX = os.path.join(os.path.dirname(__file__), "fixtures")
BASELINE = os.path.join(FIX, "gaad_baseline.json")
DRIFTED = os.path.join(FIX, "gaad_drifted.json")


def _snapshot(path):
    account, roles = load_gaad(path)
    return build_snapshot(account, roles, f"gaad:{path}")


def test_gaad_parses_roles_and_account():
    account, roles = load_gaad(BASELINE)
    assert account == "111111111111"
    names = {r["role_name"] for r in roles}
    assert names == {"app-service-role", "vendor-integration-role"}


def test_gaad_snapshot_shape():
    snap = _snapshot(BASELINE)
    assert snap["account"] == "111111111111"
    assert set(snap["roles"]) == {"app-service-role", "vendor-integration-role"}
    role = snap["roles"]["vendor-integration-role"]
    assert role["normalized"]["accounts"] == ["222222222222"]
    assert role["normalized"]["protections"] == ["ExternalId"]
    assert len(role["hash"]) == 64


def test_diff_flags_new_external_account_and_dropped_externalid():
    findings = diff(_snapshot(BASELINE), _snapshot(DRIFTED))
    by_rule = {f.rule_id for f in findings}
    # New external account 999999999999 added.
    assert "TPW-002" in by_rule
    # ExternalId condition dropped.
    assert "TPW-004" in by_rule

    external = [f for f in findings if f.rule_id == "TPW-002"]
    assert len(external) == 1
    assert external[0].severity == "critical"
    assert external[0].properties["account"] == "999999999999"

    dropped = [f for f in findings if f.rule_id == "TPW-004"]
    assert dropped[0].severity == "high"
    assert "ExternalId" in dropped[0].detail


def test_no_drift_when_identical():
    findings = diff(_snapshot(BASELINE), _snapshot(BASELINE))
    assert findings == []


def test_meets_threshold():
    assert meets("critical", "high") is True
    assert meets("medium", "high") is False
    assert meets("high", "high") is True


def test_sarif_output_is_valid():
    findings = diff(_snapshot(BASELINE), _snapshot(DRIFTED))
    doc = json.loads(render_sarif(findings))
    assert doc["version"] == "2.1.0"
    assert "runs" in doc and len(doc["runs"]) == 1
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "trust-policy-watch"
    assert len(run["tool"]["driver"]["rules"]) >= 6
    assert len(run["results"]) == len(findings)
    # critical finding surfaces as error level
    levels = {r["level"] for r in run["results"]}
    assert "error" in levels
    # security-severity present on rules
    for rule in run["tool"]["driver"]["rules"]:
        assert "security-severity" in rule["properties"]


def test_json_output_has_summary():
    findings = diff(_snapshot(BASELINE), _snapshot(DRIFTED))
    doc = json.loads(render_json(findings))
    assert doc["tool"] == "trust-policy-watch"
    assert doc["summary"]["total"] == len(findings)
    assert doc["summary"]["critical"] >= 1


def test_cli_snapshot_then_diff_fail_on(tmp_path, capsys):
    base_out = tmp_path / "baseline.json"
    rc = main(["snapshot", "--gaad", BASELINE, "-o", str(base_out)])
    assert rc == 0
    assert base_out.exists()

    # critical drift present, fail-on high -> exit 1
    rc = main(["diff", "--baseline", str(base_out), "--gaad", DRIFTED, "-f", "json", "--fail-on", "high"])
    assert rc == 1

    # same baseline vs itself -> no findings -> exit 0
    rc = main(["diff", "--baseline", str(base_out), "--gaad", BASELINE, "-f", "json", "--fail-on", "high"])
    assert rc == 0


def test_cli_fail_on_critical_ignores_high_only(tmp_path):
    # Build a baseline that only drops ExternalId (high) with no new account.
    base = json.load(open(BASELINE))
    cur = json.load(open(BASELINE))
    # drop the ExternalId condition from the vendor role in the "current" copy
    for entry in cur["RoleDetailList"]:
        if entry["RoleName"] == "vendor-integration-role":
            entry["AssumeRolePolicyDocument"]["Statement"][0].pop("Condition", None)
    base_file = tmp_path / "b.json"
    cur_file = tmp_path / "c.json"
    base_file.write_text(json.dumps(base))
    cur_file.write_text(json.dumps(cur))

    snap = tmp_path / "snap.json"
    assert main(["snapshot", "--gaad", str(base_file), "-o", str(snap)]) == 0
    # Only a high finding exists; --fail-on critical -> exit 0
    assert main(["diff", "--baseline", str(snap), "--gaad", str(cur_file), "--fail-on", "critical", "-f", "json"]) == 0
    # --fail-on high -> exit 1
    assert main(["diff", "--baseline", str(snap), "--gaad", str(cur_file), "--fail-on", "high", "-f", "json"]) == 1


def test_min_severity_filters_output(tmp_path, capsys):
    snap = tmp_path / "snap.json"
    main(["snapshot", "--gaad", BASELINE, "-o", str(snap)])
    main(["diff", "--baseline", str(snap), "--gaad", DRIFTED, "-f", "json", "--min-severity", "critical"])
    out = json.loads(capsys.readouterr().out)
    assert out["summary"]["total"] >= 1
    assert all(f["severity"] == "critical" for f in out["findings"])
