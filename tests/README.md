# Detection Rule Tests

Crafted samples for validating YARA and Sigma detection rules.

## Structure

```
tests/
  true_positives/   — Files that MUST trigger detection rules
  true_negatives/   — Files that MUST NOT trigger detection rules
  expected/         — Expected rule mappings (one .expected file per true positive)
```

## Expected Rule Mapping

Each true positive can have a corresponding file in `tests/expected/` listing the exact YARA rules it must trigger (one per line):

```
tests/true_positives/malicious_package.json        — sample
tests/expected/malicious_package.json.expected      — expected rules
```

If no `.expected` file exists, the CI just verifies the sample triggers at least one rule.

## Running Locally

```bash
# True positives (expect matches)
yara rules/yara/mini_shai_hulud.yar tests/true_positives/ -r

# True negatives (expect no matches)
yara rules/yara/mini_shai_hulud.yar tests/true_negatives/ -r
```

## Expected Results

### True Positives
| File | Expected Rules |
|------|----------------|
| `router_init_obfuscated.js` | MiniShaiHulud_RouterInit |
| `malicious_package.json` | MiniShaiHulud_PackageJson, MiniShaiHulud_RouterInit |
| `malicious_prepare_hook.json` | MiniShaiHulud_PrepareHook |
| `guardrails_dropper.py` | MiniShaiHulud_PyPI_Dropper |

### True Negatives
| File | Rationale |
|------|-----------|
| `legitimate_claude_settings.json` | Normal Claude Code config |
| `legitimate_setup.mjs` | Generic setup file |
| `legitimate_tanstack_package.json` | Clean TanStack package |
| `legitimate_node_obfuscated.js` | Obfuscated JS without malicious indicators |
| `legitimate_aws_sdk.js` | AWS SDK usage without theft patterns |
