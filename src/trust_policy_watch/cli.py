"""Command-line interface for trust-policy-watch."""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .diff import diff, meets
from .report import render
from .snapshot import build_snapshot


def _collect(args):
    """Collect ``(account, roles, source)`` from --live or --gaad."""
    if args.gaad:
        from .gaad import load_gaad

        account, roles = load_gaad(args.gaad)
        return account, roles, f"gaad:{args.gaad}"
    from .live import collect_roles

    account, roles = collect_roles(profile=args.profile)
    return account, roles, "live"


def _write(text: str, out: str | None):
    if out:
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(text + ("\n" if not text.endswith("\n") else ""))
    else:
        print(text)


def _cmd_snapshot(args) -> int:
    account, roles, source = _collect(args)
    snapshot = build_snapshot(account, roles, source)
    _write(json.dumps(snapshot, indent=2, sort_keys=True), args.output)
    sys.stderr.write(f"snapshot: {len(snapshot['roles'])} role(s) from {source}\n")
    return 0


def _cmd_diff(args) -> int:
    with open(args.baseline, encoding="utf-8") as fh:
        baseline = json.load(fh)

    account, roles, source = _collect(args)
    current = build_snapshot(account, roles, source)

    findings = diff(baseline, current)

    if args.min_severity:
        findings = [f for f in findings if meets(f.severity, args.min_severity)]

    use_color = sys.stdout.isatty() and not args.no_color and args.format == "text"
    _write(render(findings, args.format, use_color=use_color), args.output)

    if any(meets(f.severity, args.fail_on) for f in findings):
        return 1
    return 0


def _add_source_args(parser, *, with_profile=True):
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--live", action="store_true", help="read trust policies from the live AWS account via boto3 (read-only)")
    group.add_argument("--gaad", metavar="FILE", help="read trust policies offline from a get-account-authorization-details JSON file")
    if with_profile:
        parser.add_argument("--profile", help="AWS named profile to use for --live")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="trust-policy-watch",
        description="Detect drift and persistence in AWS IAM role trust policies (AssumeRolePolicyDocument). Read-only.",
    )
    parser.add_argument("-V", "--version", action="version", version=f"trust-policy-watch {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    snap = sub.add_parser("snapshot", help="capture current trust policies into a baseline JSON")
    _add_source_args(snap)
    snap.add_argument("-o", "--output", metavar="FILE", help="write baseline JSON here (default: stdout)")
    snap.set_defaults(func=_cmd_snapshot, profile=None)

    d = sub.add_parser("diff", help="compare current trust policies against a baseline and flag drift")
    d.add_argument("--baseline", required=True, metavar="FILE", help="baseline JSON produced by 'snapshot'")
    _add_source_args(d)
    d.add_argument("-f", "--format", choices=["text", "json", "sarif"], default="text", help="output format")
    d.add_argument("-o", "--output", metavar="FILE", help="write report here (default: stdout)")
    d.add_argument("--min-severity", choices=["critical", "high", "medium", "low", "info"], help="only report findings at or above this severity")
    d.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "info"], default="high", help="exit non-zero if any finding is at or above this severity (default: high)")
    d.add_argument("--no-color", action="store_true", help="disable ANSI colors in text output")
    d.set_defaults(func=_cmd_diff, profile=None)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except FileNotFoundError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2
    except json.JSONDecodeError as exc:
        sys.stderr.write(f"error: invalid JSON: {exc}\n")
        return 2


if __name__ == "__main__":
    sys.exit(main())
