# Firewall Policy Audit

A lightweight Python tool that audits firewall rule exports for common
misconfigurations — overly permissive rules, disabled logging, undocumented
rules, and shadowed (redundant) rules. Built for periodic policy hygiene
reviews against least-privilege and CIS-benchmark principles.

Standard library only. No dependencies to install.

## Checks performed

| ID      | Severity | What it flags |
|---------|----------|---------------|
| FWA-001 | CRITICAL | Allow rule with ANY source, ANY destination, ANY service |
| FWA-002 | HIGH     | Allow rule with ANY source |
| FWA-003 | MEDIUM   | Allow rule with ANY service |
| FWA-004 | MEDIUM   | Allow rule with logging disabled |
| FWA-005 | LOW      | Allow rule with no description |
| FWA-006 | INFO     | Disabled rule (cleanup candidate) |
| FWA-007 | HIGH     | Rule shadowed by an earlier identical rule (redundant) |

## Usage

```bash
python3 audit.py samples/sample_paloalto_rules.csv
python3 audit.py samples/sample_asa_acls.csv
```

Input is a CSV with columns:
`rule_name, source, destination, service, action, log, status, description`

Exit code is `1` when HIGH or CRITICAL findings exist, so the tool can gate
a CI pipeline or scheduled audit job; `0` when clean.

## Example output

```
Firewall Policy Audit — samples/sample_paloalto_rules.csv
Rules evaluated: 10
======================================================================

[CRITICAL]
  FWA-001: Rule 'Allow-Any-Any-Temp' allows ANY source to ANY destination on ANY service.

[HIGH]
  FWA-007: Rule 'Allow-Web-Outbound-Dup' is shadowed by an earlier identical rule — it is redundant.
  FWA-002: Rule 'Allow-Vendor-Access' allows ANY source to '10.30.4.0/24'. Restrict to known subnets.

[MEDIUM]
  FWA-004: Rule 'Allow-Any-Any-Temp' has logging disabled — allowed traffic will be invisible to the SOC.
  FWA-004: Rule 'Allow-Vendor-Access' has logging disabled — allowed traffic will be invisible to the SOC.

[LOW]
  FWA-005: Rule 'Allow-Vendor-Access' has no description — undocumented rules cannot be reviewed.

[INFO]
  FWA-006: Rule 'Old-Decommissioned-Rule' is disabled — remove it if permanently decommissioned.

======================================================================
Summary by severity:
  CRITICAL 1
  HIGH     2
  MEDIUM   2
  LOW      1
  INFO     1
  TOTAL    7
```

## Repository structure

```
firewall-policy-audit/
├── audit.py                        # the audit tool
├── samples/
│   ├── sample_paloalto_rules.csv   # fictional Palo Alto-style rule export
│   └── sample_asa_acls.csv         # fictional ASA-style ACL export
└── README.md
```

## Notes

- All sample data is fictional and sanitized — never commit real firewall
  exports, internal IP schemes, or credentials to a public repository.
- Tested on Python 3.8+.

## Roadmap

- [ ] HTML report output
- [ ] Palo Alto XML / ASA running-config parsers
- [ ] Rule-hit-count correlation to flag unused rules
