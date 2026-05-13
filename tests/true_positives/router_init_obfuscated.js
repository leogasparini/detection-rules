// Simulated Mini Shai-Hulud obfuscated payload (true positive)
// This file contains enough indicators to trigger MiniShaiHulud_RouterInit

var _0x253b = ['test'];
var _0x360f = function() { while(!![]){ try { var result = parseInt(_0x253b[0]); } catch(e) {} } };

// beautify decode layer
function beautify(input) { return input; }

// Credential harvesting
var imds = "169.254.169.254/latest/api/token";
var vault = "vault.svc.cluster.local";

// Session exfil
var exfil = "filev2.getsession";
var proto1 = "signalservice.Envelope";
var proto2 = "signalservice.Content";
var proto3 = "signalservice.DataMessage";

// Daemonization
var guard = "__DAEMONIZED";

// Persistence
var persist = ".claude/router_runtime.js";

// Repo poisoning
var mutation = "createCommitOnBranch";
var author = "claude@users.noreply.github.com";

// npm worm
var oidc1 = "ACTIONS_ID_TOKEN_REQUEST_TOKEN";
var oidc2 = "ACTIONS_ID_TOKEN_REQUEST_URL";
var npm_api = "registry.npmjs.org/-/npm/v1/tokens";
