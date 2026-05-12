# Detection Rules

Detection rules for threat intelligence and incident response. Contains YARA rules for file-based detection and Sigma rules for log-based detection.

## Structure

```
detection-rules/
├── yara/              # YARA rules (.yar)
├── sigma/             # Sigma rules (.yml), one rule per file
│   ├── file_event/
│   ├── process_creation/
│   ├── network_connection/
│   └── dns_query/
├── docs/              # Incident write-ups and references
└── .kiro/             # Kiro agent configuration
```

## Rule Requirements

### YARA Rules
- Each rule must have `meta.description` and `meta.author`
- Include `meta.mitre_attack` with technique IDs (e.g., `T1195.002`)
- Include `meta.reference` with source URL
- Include `meta.date` in YYYY-MM-DD format
- Include `meta.severity` (critical, high, medium, low)
- Test rules with `yara <rule.yar> <target> -r` before committing

### Sigma Rules
- One rule per file (no multi-document YAML)
- Must include: `title`, `id` (UUID), `status`, `description`, `author`, `date`, `references`, `tags` (MITRE), `logsource`, `detection`, `falsepositives`, `level`
- Tags use format: `attack.t1234.001`, `attack.tactic-name`
- File naming: lowercase, underscores, descriptive (e.g., `mini_shai_hulud_file_creation.yml`)
- Place in subdirectory matching `logsource.category`

## Conversion

Sigma rules are converted to CrowdStrike LogScale format using pySigma:
```bash
python scripts/02_convert_sigma_rule_simple.py <rule.yml>
```
# detection-rules
