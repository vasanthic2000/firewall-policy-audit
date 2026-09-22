#!/usr/bin/env python3
"""
firewall-policy-audit.py — Audit firewall rule exports for common misconfigurations.

Reads a CSV export of firewall rules and flags risky patterns such as
any-any-any allow rules, overly broad sources/services, disabled logging,
undocumented rules, and shadowed (redundant) rules.

Usage:
    python3 audit.py samples/sample_paloalto_rules.csv
    python3 audit.py samples/sample_asa_acls.csv

Expected CSV columns:
    rule_name, source, destination, service, action, log, status, description

Exit codes:
    0 - no HIGH or CRITICAL findings
    1 - HIGH or CRITICAL findings present
    2 - usage / input error

Standard library only — no dependencies to install.
"""

import argparse
import csv
import sys
from collections import Counter

SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def norm(value):
    """Normalize a field for comparison."""
    return (value or "").strip().lower()


def is_any(value):
    """True when a field is effectively 'any'."""
    return norm(value) in ("any", "0.0.0.0/0", "any/any", "::/0")


def audit_rule(rule, seen_signatures):
    """Run all checks against a single rule. Returns a list of findings.

    Each finding is a tuple: (severity, check_id, message)
    """
    findings = []
    name = rule.get("rule_name", "?").strip() or "?"
    action = norm(rule.get("action"))
    src, dst, svc = rule.get("source"), rule.get("destination"), rule.get("service")
    log = norm(rule.get("log"))
    status = norm(rule.get("status"))
    desc = (rule.get("description") or "").strip()

    if status == "disabled":
        findings.append(("INFO", "FWA-006",
                         f"Rule '{name}' is disabled — remove it if permanently decommissioned."))
        return findings  # disabled rules are not evaluated further

    if action == "allow":
        if is_any(src) and is_any(dst) and is_any(svc):
            findings.append(("CRITICAL", "FWA-001",
                             f"Rule '{name}' allows ANY source to ANY destination on ANY service."))
        elif is_any(src):
            findings.append(("HIGH", "FWA-002",
                             f"Rule '{name}' allows ANY source to '{dst}'. Restrict to known subnets."))
        elif is_any(svc):
            findings.append(("MEDIUM", "FWA-003",
                             f"Rule '{name}' allows ANY service to '{dst}'. Restrict to required ports."))

        if log in ("no", "false", "disabled", ""):
            findings.append(("MEDIUM", "FWA-004",
                             f"Rule '{name}' has logging disabled — allowed traffic will be invisible to the SOC."))

        if not desc:
            findings.append(("LOW", "FWA-005",
                             f"Rule '{name}' has no description — undocumented rules cannot be reviewed."))

        # Shadowed / redundant rule detection: an identical allow signature
        # already appeared earlier, so this rule can never add new access.
        signature = (norm(src), norm(dst), norm(svc), action)
        if signature in seen_signatures:
            findings.append(("HIGH", "FWA-007",
                             f"Rule '{name}' is shadowed by an earlier identical rule — it is redundant."))
        else:
            seen_signatures.add(signature)

    return findings


def load_rules(path):
    try:
        with open(path, newline="", encoding="utf-8-sig") as fh:
            reader = csv.DictReader(fh)
            required = {"rule_name", "source", "destination", "service",
                        "action", "log", "status", "description"}
            missing = required - set(reader.fieldnames or [])
            if missing:
                print(f"ERROR: missing columns: {', '.join(sorted(missing))}", file=sys.stderr)
                sys.exit(2)
            return list(reader)
    except FileNotFoundError:
        print(f"ERROR: file not found: {path}", file=sys.stderr)
        sys.exit(2)


def print_report(path, rules, all_findings):
    print(f"\nFirewall Policy Audit — {path}")
    print(f"Rules evaluated: {len(rules)}")
    print("=" * 70)

    if not all_findings:
        print("No findings. Policy is clean against all checks.")
    else:
        ordered = sorted(all_findings, key=lambda f: SEVERITY_RANK[f[0]])
        current = None
        for severity, check_id, message in ordered:
            if severity != current:
                current = severity
                print(f"\n[{severity}]")
            print(f"  {check_id}: {message}")

    print("\n" + "=" * 70)
    print("Summary by severity:")
    counts = Counter(sev for sev, _, _ in all_findings)
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        print(f"  {sev:<8} {counts.get(sev, 0)}")
    print(f"  {'TOTAL':<8} {len(all_findings)}")


def main():
    parser = argparse.ArgumentParser(
        description="Audit a firewall rule CSV export for common misconfigurations.")
    parser.add_argument("csv_file", help="Path to the firewall rules CSV file")
    args = parser.parse_args()

    rules = load_rules(args.csv_file)
    seen = set()
    all_findings = []
    for rule in rules:
        all_findings.extend(audit_rule(rule, seen))

    print_report(args.csv_file, rules, all_findings)

    bad = sum(1 for sev, _, _ in all_findings if sev in ("CRITICAL", "HIGH"))
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
