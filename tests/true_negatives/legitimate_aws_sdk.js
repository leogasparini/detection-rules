// Legitimate AWS SDK usage from Node.js (true negative)
// Contains IMDS reference but not in malicious context
const { EC2MetadataCredentials } = require('aws-sdk');
const creds = new EC2MetadataCredentials({ httpOptions: { timeout: 5000 } });
console.log("Fetching credentials from instance metadata");
