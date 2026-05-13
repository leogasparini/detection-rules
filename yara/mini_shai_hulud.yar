rule MiniShaiHulud_RouterInit {
    meta:
        description = "Detects Mini Shai-Hulud supply-chain malware (router_init.js / router_runtime.js / tanstack_runner.js)"
        author = "SecEng"
        date = "2026-05-12"
        reference1 = "https://socket.dev/blog/tanstack-npm-packages-compromised-mini-shai-hulud-supply-chain-attack"
        reference2 = "https://safedep.io/mass-npm-supply-chain-attack-tanstack-mistral/"
        severity = "high"
        mitre_attack = "T1195.002, T1059.007, T1552.001, T1071.001, T1547.004, T1496, T1580"
        mitre_tactics = "Initial Access, Execution, Credential Access, Command and Control, Persistence, Lateral Movement"

    strings:
        // Obfuscator pattern - string array rotation with while(true) loop
        $obf_loop = "while(!![]){" ascii
        $obf_dispatcher = "_0x253b" ascii
        $obf_parseInt = "parseInt(_0x" ascii

        // Daemonization guard
        $daemon_env = "__DAEMONIZED" ascii

        // beautify() XOR decode layer
        $beautify_call = "beautify(" ascii

        // Session P2P exfiltration
        $session_exfil = "filev2.getsession" ascii
        $proto_envelope = "signalservice.Envelope" ascii
        $proto_content = "signalservice.Content" ascii
        $proto_datamsg = "signalservice.DataMessage" ascii

        // Credential harvesting targets
        $aws_imds = "169.254.169.254/latest/api/token" ascii
        $vault_k8s = "vault.svc.cluster.local" ascii
        $k8s_sa = "/var/run/secrets/kubernetes.io/serviceaccount" ascii

        // npm worm propagation
        $oidc_token_req = "ACTIONS_ID_TOKEN_REQUEST_TOKEN" ascii
        $oidc_token_url = "ACTIONS_ID_TOKEN_REQUEST_URL" ascii
        $npm_tokens_api = "registry.npmjs.org/-/npm/v1/tokens" ascii

        // Repository poisoning via GraphQL
        $graphql_commit = "createCommitOnBranch" ascii
        $spoof_author = "claude@users.noreply.github.com" ascii

        // Persistence - campaign-specific paths only
        $persist_claude = ".claude/router_runtime.js" ascii

        // Malicious optionalDependencies injection
        $tanstack_setup = "github:tanstack/router#79ac49ee" ascii

        // Known file hashes (as byte patterns in case embedded)
        $hash_variant1 = "ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c" ascii nocase
        $hash_variant2 = "2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96" ascii nocase

    condition:
        filesize < 5MB and (
            // Match by known hash references
            any of ($hash_variant*) or
            // Match obfuscated payload with credential theft indicators
            (2 of ($obf_*) and 2 of ($aws_imds, $vault_k8s, $k8s_sa, $oidc_token_req, $oidc_token_url)) or
            // Match Session exfil protocol
            ($session_exfil and 2 of ($proto_*)) or
            // Match worm propagation
            ($npm_tokens_api and $oidc_token_req and $oidc_token_url) or
            // Match persistence + daemonization
            ($daemon_env and $persist_claude) or
            // Match repo poisoning
            ($graphql_commit and $spoof_author) or
            // Match tanstack-specific injection
            $tanstack_setup or
            // Match beautify decode layer with obfuscation
            ($beautify_call and 2 of ($obf_*))
        )
}

rule MiniShaiHulud_PackageJson {
    meta:
        description = "Detects package.json modified by Mini Shai-Hulud (malicious optionalDependencies)"
        author = "SecEng"
        date = "2026-05-12"
        reference1 = "https://socket.dev/blog/tanstack-npm-packages-compromised-mini-shai-hulud-supply-chain-attack"
        reference2 = "https://safedep.io/mass-npm-supply-chain-attack-tanstack-mistral/"
        severity = "high"
        mitre_attack = "T1195.002, T1204.002"
        mitre_tactics = "Initial Access, Execution"

    strings:
        $dep = "github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c" ascii
        $pkg_name = "@tanstack/setup" ascii

    condition:
        filesize < 100KB and all of them
}

rule MiniShaiHulud_PrepareHook {
    meta:
        description = "Detects malicious prepare lifecycle hook executing tanstack_runner.js"
        author = "SecEng"
        date = "2026-05-12"
        reference1 = "https://socket.dev/blog/tanstack-npm-packages-compromised-mini-shai-hulud-supply-chain-attack"
        reference2 = "https://safedep.io/mass-npm-supply-chain-attack-tanstack-mistral/"
        severity = "high"
        mitre_attack = "T1059.007, T1204.002"
        mitre_tactics = "Execution"

    strings:
        $prepare = "bun run tanstack_runner.js" ascii

    condition:
        filesize < 10KB and $prepare
}

rule MiniShaiHulud_PyPI_Dropper {
    meta:
        description = "Detects Mini Shai-Hulud PyPI variant (mistralai/guardrails-ai) downloading transformers.pyz from attacker infrastructure"
        author = "SecEng"
        date = "2026-05-12"
        reference1 = "https://socket.dev/blog/tanstack-npm-packages-compromised-mini-shai-hulud-supply-chain-attack"
        reference2 = "https://safedep.io/mass-npm-supply-chain-attack-tanstack-mistral/"
        severity = "high"
        mitre_attack = "T1195.002, T1105, T1059.006"
        mitre_tactics = "Initial Access, Execution, Command and Control"

    strings:
        $c2_domain = "git-tanstack.com" ascii
        $payload_url = "git-tanstack.com/transformers.pyz" ascii
        $tmp_path = "/tmp/transformers.pyz" ascii
        $subprocess = "subprocess.run" ascii
        $urllib = "urllib.request.urlopen" ascii

    condition:
        filesize < 1MB and (
            // Direct URL match
            $payload_url or
            // Attacker domain + staging path
            ($c2_domain and $tmp_path) or
            // Download + execute pattern with staging path
            ($urllib and $tmp_path and $subprocess)
        )
}
