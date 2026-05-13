# Detection Rules

[![Test YARA Rules](https://github.com/leogasparini/detection-rules/actions/workflows/test-yara.yml/badge.svg)](https://github.com/leogasparini/detection-rules/actions/workflows/test-yara.yml)
[![Test Sigma Rules](https://github.com/leogasparini/detection-rules/actions/workflows/test-sigma.yml/badge.svg)](https://github.com/leogasparini/detection-rules/actions/workflows/test-sigma.yml)

YARA and Sigma detection rules generated from threat intelligence and incident response.

## Structure

```
rules/
  yara/        — File-based detection rules
  sigma/       — Log-based detection rules (one rule per file)
    file_event/
    process_creation/
    network_connection/
    dns_query/
tests/         — YARA true positive/negative test samples
docs/          — Incident references
```

## Usage

### YARA
```bash
yara rules/yara/<rule>.yar /path/to/scan -r
```

### Sigma
Convert to CrowdStrike LogScale:
```bash
python scripts/02_convert_sigma_rule_simple.py rules/sigma/<category>/<rule>.yml
```

## Rule Standards

- MITRE ATT&CK mapping on every rule
- CVE references when applicable
- One Sigma rule per file, no multi-document YAML
- YARA rules require `meta.description` and `meta.author`
