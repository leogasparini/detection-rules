# Detection Rules Project Steering

You are working in the `detection-rules` project. Your role is to process security incidents and threat intelligence into actionable detection rules (YARA and Sigma).

## Core Workflow

When processing an incident or threat intelligence report:

1. **Analyze the source** — Extract IOCs (hashes, domains, IPs, file paths, process behaviors), TTPs, and affected software.
2. **Map to MITRE ATT&CK** — Identify relevant tactics and techniques. Use sub-technique IDs where applicable (e.g., `T1195.002` not just `T1195`).
3. **Identify CVEs** — If the incident exploits known vulnerabilities, include CVE references in rule metadata.
4. **Generate YARA rules** — For file-based indicators (malware samples, injected scripts, modified configs).
5. **Generate Sigma rules** — For behavioral/log-based indicators (process execution, network connections, file creation, DNS queries).
6. **Validate** — Run YARA syntax check and YAML validation on all generated rules.
7. **Organize** — Place rules in the correct directories per the project structure.

## Rule Generation Standards

### YARA Rules (`yara/`)

Every YARA rule MUST contain:
```
rule <RuleName> {
    meta:
        description = "<what it detects>"
        author = "SecEng"
        date = "<YYYY-MM-DD>"
        reference = "<source URL>"
        severity = "<critical|high|medium|low>"
        mitre_attack = "<T-codes comma separated>"
        mitre_tactics = "<tactic names comma separated>"
        cve = "<CVE-YYYY-NNNNN if applicable, otherwise omit>"

    strings:
        <detection strings>

    condition:
        <detection logic>
}
```

Guidelines:
- Use layered detection logic (multiple independent signal combinations) to reduce false negatives while keeping false positives low.
- Prefer `ascii` modifier for string matches unless binary content.
- Use `filesize` constraints to scope detection.
- Group strings by function (e.g., obfuscation indicators, C2 indicators, persistence indicators).
- Test with `yara <file.yar> /tmp/yara_test -r` using synthetic test files.

### Sigma Rules (`sigma/`)

Every Sigma rule MUST contain these fields:
```yaml
title: <concise detection title>
id: <UUID v4>
status: experimental
description: <what it detects and why>
references:
    - <source URLs>
author: SecEng
date: <YYYY-MM-DD>
tags:
    - attack.<tactic>
    - attack.t<technique_id>
logsource:
    category: <file_event|process_creation|network_connection|dns_query|...>
    product: <windows|linux|...>
detection:
    <selection and condition logic>
falsepositives:
    - <known false positive scenarios>
level: <critical|high|medium|low|informational>
```

Guidelines:
- ONE rule per file. Never use YAML multi-document (`---`) separators.
- File goes in subdirectory matching `logsource.category`.
- File naming: `<campaign_or_cve>_<detection_type>.yml`
- Always validate YAML syntax after creation.
- Include CVE in description and references if applicable.
- Use `|contains`, `|endswith`, `|startswith` modifiers appropriately.
- For Windows paths use `\`, for Linux use `/`.

## MITRE ATT&CK Mapping Reference

Common supply-chain and malware techniques:
- `T1195.002` — Supply Chain Compromise: Software Supply Chain
- `T1059.007` — Command and Scripting Interpreter: JavaScript
- `T1059.006` — Command and Scripting Interpreter: Python
- `T1552.001` — Unsecured Credentials: Credentials in Files
- `T1552.005` — Unsecured Credentials: Cloud Instance Metadata API
- `T1071.001` — Application Layer Protocol: Web Protocols
- `T1547.004` — Boot or Logon Autostart Execution
- `T1105` — Ingress Tool Transfer
- `T1204.002` — User Execution: Malicious File
- `T1580` — Cloud Infrastructure Discovery
- `T1048` — Exfiltration Over Alternative Protocol
- `T1036` — Masquerading

## Validation

After generating rules, always:
1. Run `yara <rule.yar> /dev/null` to check YARA syntax.
2. Run `python3 -c "import yaml; yaml.safe_load(open('<file.yml>'))"` to validate Sigma YAML.
3. Create synthetic test files in `/tmp/yara_test/` to confirm YARA rules fire correctly.
4. Confirm benign files do NOT trigger rules (false positive check).
5. Clean up test files after validation.

## Output Summary

After processing an incident, provide:
- Number of YARA rules created
- Number of Sigma rules created
- MITRE techniques covered
- CVEs referenced (if any)
- Any detection gaps or limitations noted
