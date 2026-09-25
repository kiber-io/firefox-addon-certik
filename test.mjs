import assert from "node:assert/strict";
import { X509Certificate } from "node:crypto";
import { rootCertificates } from "node:tls";
import { connectionIndicator, describeTrust } from "./status.mjs";
import { parseCertificate } from "./x509.mjs";
import { formatDn, toPem } from "./popup.mjs";

assert.match(describeTrust({ state: "insecure" }).title, /No secure/);
assert.match(describeTrust({ state: "secure", certificates: [{ isBuiltInRoot: true }] }).detail, /Mozilla Root Store/);
assert.match(describeTrust({ state: "secure", certificates: [{ isBuiltInRoot: false }] }).detail, /operating-system/);
assert.match(describeTrust({ state: "secure", isUntrusted: true }).title, /exception/);
assert.match(describeTrust({ state: "secure", isDomainMismatch: true }).detail, /hostname mismatch/);
assert.equal(connectionIndicator({ state: "secure" }).color, "green");
assert.equal(connectionIndicator({ state: "secure", isUntrusted: true }).color, "yellow");
assert.equal(connectionIndicator({ state: "insecure" }).color, "gray");

const parsed = parseCertificate(new X509Certificate(rootCertificates[0]).raw);
assert.equal(parsed.version, 3);
assert.ok(parsed.signatureAlgorithm);
assert.ok(parsed.publicKeyAlgorithm);
assert.equal(formatDn("OID.1.2.643.100.1=#120D31303737373631303837313137,OID.1.2.643.100.4=#120A37373138363638383837,CN=*.ptsecurity.com"), "OGRN=1077761087117,INNLE=7718668887,CN=*.ptsecurity.com");
assert.match(toPem(Uint8Array.from([1, 2, 3])), /BEGIN CERTIFICATE/);

console.log("OK");
