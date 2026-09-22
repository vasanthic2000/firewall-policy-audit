#!/usr/bin/env python3
"""
firewall-policy-audit.py — Audit firewall rule exports for common misconfigurations.

Check definitions live in checks.yaml, so the audit policy can be tuned
without touching code. Reads a CSV export of firewall rules and flags
risky patterns such as any-any-any allow rules, overly broad
sources/services, disabled logging, undocumented rules, and shadowed
(redundant) rules.

Usage:
    pip install -r requirements.txt
    python3 audit.py samples/sample_paloalto_rules.csv
    python3 audit.py samples/sample_asa_acls.csv --config my_checks.yaml

Expected CSV columns:
    rule_name, source, destination, service, action, log, status, description

Exit codes:
    0 - no findings at or above the fail_on severities (see checks.yaml)
    1 - findings at or above the fail_on severities present
    2 - usage / input / configuration error
"""

import argparse
import csv
import sys
from collections import Counter
from pathlib import Path

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML is required. Install it with: pip install -r requirements.txt",
          file=sys.stderr)
    sys.exit(2)

SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
BASE_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG = BASE_DIR / "checks.yaml"


def norm(value):
    """Normalize a field for comparison."""
    return (value or "").strip().lower()


def is_any(value):
    """True when a field is effectively 'any'."""
    return norm(value) in ("any", "0.0.0.0/0", "any/any", "::/0")


def condition_matches(rule, field, expected):
    """Evaluate one condition of a pattern check against a rule."""
    actual = rule.get(field, "")
    if expected == "any":
        return is_any(actual)
    if expected == "empty":
        return not (actual or "").strip()
    return norm(actual) == norm(expected)


def render(template, rule):
    """Fill {name} / {source} / {destination} / {service} / {action} placeholders."""
    return template.format(
        name=(rule.get("rule_name") or "?").strip() or "?",
        source=(rule.get("source") or "").strip(),
        destination=(rule.get("destination") or "").strip(),
        service=(rule.get("service") or "").strip(),
        action=(rule.get("action") or "").strip(),
    )


def load_config(path):
    try:
        with open(path, encoding="utf-8") as fh:
            config = yaml.safe_load(fh) or {}
    except FileNotFoundError:
        print(f"ERROR: config file not found: {path}", file=sys.stderr)
        sys.exit(2)
    except yaml.YAMLError as exc:
        print(f"ERROR: invalid YAML in {path}: {exc}", file=sys.stderr)
        sys.exit(2)

    # Validate the configuration early with clear errors.
    for check in config.get("checks", []):
        for key in ("id", "severity", "type", "message"):
            if key not in check:
                print(f"ERROR: check is missing required key '{key}': {check}",
                      file=sys.stderr)
                sys.exit(2)
        if check["severity"].upper() not in SEVERITY_RANK:
            print(f"ERROR: check {check['id']} has unknown severity "
                  f"'{check['severity']}'", file=sys.stderr)
            sys.exit(2)
        if check["type"] not in ("pattern", "no_logging", "no_description",
                                 "disabled", "shadowed"):
            print(f"ERROR: check {check['id']} has unknown type "
                  f"'{check['type']}'", file=sys.stderr)
            sys.exit(2)
    return config


class AuditEngine:
    """Evaluates firewall rules against the checks defined in checks.yaml."""

    def __init__(self, config):
        self.fail_on = [s.upper() for s in config.get("fail_on", ["CRITICAL", "HIGH"])]
        self.ignore_rules = set(config.get("ignore_rules", []) or [])
        self.checks = [c for c in config.get("checks", []) if c.get("enabled", True)]
        self._seen_signatures = set()

    def evaluate(self, rule):
        """Run all enabled checks against one rule. Returns a list of findings.

        Each finding is a tuple: (severity, check_id, message)
        """
        name = (rule.get("rule_name") or "").strip()
        if name in self.ignore_rules:
            return []

        disabled = norm(rule.get("status")) == "disabled"
        findings, matched = [], set()
        for check in self.checks:
            # Disabled rules are only reported as cleanup candidates,
            # never evaluated against the active-policy checks.
            if disabled and check["type"] != "disabled":
                continue
            if any(m in matched for m in check.get("skip_when_matched", []) or []):
                continue
            if self._fires(check, rule):
                findings.append((check["severity"].upper(), check["id"],
                                 render(check["message"], rule)))
                matched.add(check["id"])
        return findings

    def _fires(self, check, rule):
        ctype = check["type"]
        if ctype == "pattern":
            return all(condition_matches(rule, field, expected)
                       for field, expected in (check.get("conditions") or {}).items())
        if ctype == "no_logging":
            return norm(rule.get("action")) == "allow" and \
                norm(rule.get("log")) in ("no", "false", "disabled", "")
        if ctype == "no_description":
            return norm(rule.get("action")) == "allow" and \
                not (rule.get("description") or "").strip()
        if ctype == "disabled":
            return norm(rule.get("status")) == "disabled"
        if ctype == "shadowed":
            if norm(rule.get("action")) != "allow":
                return False
            signature = (norm(rule.get("source")), norm(rule.get("destination")),
                         norm(rule.get("service")), norm(rule.get("action")))
            if signature in self._seen_signatures:
                return True
            self._seen_signatures.add(signature)
            return False
        raise ValueError(f"Unknown check type: {ctype}")  # unreachable: validated on load


def load_rules(path):
    try:
        with open(path, newline="", encoding="utf-8-sig") as fh:
            reader = csv.DictReader(fh)
            required = {"rule_name", "source", "destination", "service",
                        "action", "log", "status", "description"}
            missing = required - set(reader.fieldnames or [])
            if missing:
                print(f"ERROR: missing columns: {', '.join(sorted(missing))}",
                      file=sys.stderr)
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
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        print(f"  {sev:<8} {counts.get(sev, 0)}")
    print(f"  {'TOTAL':<8} {len(all_findings)}")


def main():
    parser = argparse.ArgumentParser(
        description="Audit a firewall rule CSV export for common misconfigurations.")
    parser.add_argument("csv_file", help="Path to the firewall rules CSV file")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG),
                        help="Path to checks.yaml (default: checks.yaml next to the script)")
    args = parser.parse_args()

    config = load_config(args.config)
    engine = AuditEngine(config)
    rules = load_rules(args.csv_file)

    all_findings = []
    for rule in rules:
        all_findings.extend(engine.evaluate(rule))

    print_report(args.csv_file, rules, all_findings)

    bad = sum(1 for sev, _, _ in all_findings if sev in engine.fail_on)
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
