# Detection Rule Tests

Crafted samples for validating YARA and Sigma detection rules.

## Structure

```
tests/
  true_positives/   — Files that MUST trigger detection rules
  true_negatives/   — Files that MUST NOT trigger detection rules
```

## Running YARA Tests

```bash
# True positives (expect matches)
yara yara/mini_shai_hulud.yar tests/true_positives/ -r

# True negatives (expect no matches)
yara yara/mini_shai_hulud.yar tests/true_negatives/ -r
```

## Expected Results

### True Positives
| File | Expected Rule |
|------|---------------|
| `router_init_obfuscated.js` | MiniShaiHulud_RouterInit |
| `malicious_package.json` | MiniShaiHulud_PackageJson |
| `malicious_prepare_hook.json` | MiniShaiHulud_PrepareHook |
| `guardrails_dropper.py` | MiniShaiHulud_PyPI_Dropper |

### True Negatives
| File | Rationale |
|------|-----------|
| `legitimate_claude_settings.json` | Normal Claude Code config |
| `legitimate_setup.mjs` | Generic setup file |
| `legitimate_tanstack_package.json` | Clean TanStack package |
| `legitimate_node_obfuscated.js` | Obfuscated but no malicious indicators |
| `legitimate_aws_sdk.js` | AWS SDK usage without theft patterns |
