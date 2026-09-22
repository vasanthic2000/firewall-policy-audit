# Firewall Policy Audit

A lightweight Python tool that audits firewall rule exports for common
misconfigurations — overly permissive rules, disabled logging, undocumented
rules, and shadowed (redundant) rules. Built for periodic policy hygiene
reviews against least-privilege and CIS-benchmark principles.

All check definitions live in `checks.yaml`, so the audit policy can be
tuned without touching code.

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
python3 audit.py samples/sample_paloalto_rules.csv
python3 audit.py samples/sample_asa_acls.csv
python3 audit.py my_rules.csv --config my_checks.yaml
```

Input is a CSV with columns:
`rule_name, source, destination, service, action, log, status, description`

Exit code is `1` when findings at or above the `fail_on` severities exist
(configured in `checks.yaml`), so the tool can gate a CI pipeline or
scheduled audit job; `0` when clean.

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

## Configuration (`checks.yaml`)

Each check is a block with an `id`, `severity`, `enabled` flag, `type`,
`message`, and `remediation`. Five check types are supported:

- `pattern` — fires when all `conditions` match. A condition value of
  `"any"` matches any/0.0.0.0/0/::/0; `"empty"` matches a blank field.
- `no_logging` — allow rules with logging disabled.
- `no_description` — allow rules with no description.
- `disabled` — disabled rules (reported only as cleanup candidates).
- `shadowed` — an identical allow rule appeared earlier in the file.

Top-level options:

```yaml
fail_on: [CRITICAL, HIGH]   # severities that cause a non-zero exit
ignore_rules: []            # rule names to skip (documented exceptions)
```

### Disabling a check

```yaml
  - id: FWA-005
    severity: LOW
    enabled: false          # skip undocumented-rule findings
    ...
```

### Adding a custom check

```yaml
  - id: FWA-100
    severity: MEDIUM
    enabled: true
    type: pattern
    description: "Allow rule to the DB subnet on a non-DB service"
    message: "Rule '{name}' allows '{service}' to DB subnet '{destination}'."
    remediation: "Confirm the service is required for database access."
    conditions:
      action: allow
      destination: 10.50.2.0/24
```

Messages support `{name}`, `{source}`, `{destination}`, `{service}`,
and `{action}` placeholders filled from the rule.

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
  FWA-003: Rule 'Allow-Vendor-Access' allows ANY service to '10.30.4.0/24'. Restrict to required ports.
  FWA-004: Rule 'Allow-Vendor-Access' has logging disabled — allowed traffic will be invisible to the SOC.

[LOW]
  FWA-005: Rule 'Allow-Vendor-Access' has no description — undocumented rules cannot be reviewed.

[INFO]
  FWA-006: Rule 'Old-Decommissioned-Rule' is disabled — remove it if permanently decommissioned.

======================================================================
Summary by severity:
  CRITICAL 1
  HIGH     2
  MEDIUM   3
  LOW      1
  INFO     1
  TOTAL    8
```

## Repository structure

```
firewall-policy-audit/
├── audit.py                        # the audit engine
├── checks.yaml                     # check definitions (tune without touching code)
├── requirements.txt                # Python dependencies
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
