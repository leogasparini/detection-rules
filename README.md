# Detection Rules

YARA and Sigma detection rules generated from threat intelligence and incident response.

## Structure

```
yara/          — File-based detection rules
sigma/         — Log-based detection rules (one rule per file)
  file_event/
  process_creation/
  network_connection/
  dns_query/
docs/          — Incident references
```

## Usage

### YARA
```bash
yara yara/<rule>.yar /path/to/scan -r
```

### Sigma
Convert to CrowdStrike LogScale:
```bash
python scripts/02_convert_sigma_rule_simple.py sigma/<category>/<rule>.yml
```

## Rule Standards

- MITRE ATT&CK mapping on every rule
- CVE references when applicable
- One Sigma rule per file, no multi-document YAML
- YARA rules require `meta.description` and `meta.author`
