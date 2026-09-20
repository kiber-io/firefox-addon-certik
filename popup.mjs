import { parseCertificate } from "./x509.mjs";
import { describeTrust, hasCertificateException } from "./status.mjs";

const text = (value) => value ?? "—";
const yesNo = (value) => value === undefined ? "—" : value ? "yes" : "no";
const date = (value) => value ? new Date(value).toLocaleString("en-US") : "—";
const html = (value) => String(text(value)).replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" })[char]);

function rows(items) {
  return `<dl class="grid">${items.map(([label, value, code = false]) =>
    `<dt class="label">${label}</dt><dd>${code ? `<code>${html(value)}</code>` : html(value)}</dd>`
  ).join("")}</dl>`;
}

function certificate(cert, index, total) {
  const role = index === 0 ? "site certificate" : index === total - 1 ? "chain anchor" : "intermediate CA";
  let parsed = {};
  try { parsed = cert.rawDER ? parseCertificate(cert.rawDER) : {}; } catch (error) { parsed.parseError = error.message; }
  const list = (values) => values?.length ? values.join("; ") : undefined;
  return `<details ${index === 0 ? "open" : ""}>
    <summary>${index + 1}. ${html(cert.subject)} <span class="pill">${role}</span></summary>
    ${rows([
      ["Subject", cert.subject],
      ["Issuer", cert.issuer],
      ["Subject Alternative Names", list(parsed.alternativeNames)],
      ["Extended Key Usage", list(parsed.extendedKeyUsage)],
      ["Key Usage", list(parsed.keyUsage)],
      ["Certificate Authority", yesNo(parsed.isCA)],
      ["Path Length Constraint", parsed.pathLength],
      ["X.509 Version", parsed.version ? `v${parsed.version}` : undefined],
      ["Signature Algorithm", parsed.signatureAlgorithm],
      ["Public Key", parsed.publicKeyAlgorithm],
      ["Certificate Policies", list(parsed.policies)],
      ["Serial Number", cert.serialNumber, true],
      ["Valid From", date(cert.validity?.start)],
      ["Valid Until", date(cert.validity?.end)],
      ["Built-in Root", yesNo(cert.isBuiltInRoot)],
      ["SHA-256", cert.fingerprint?.sha256, true],
      ["SHA-1", cert.fingerprint?.sha1, true],
      ["Public Key SHA-256", cert.subjectPublicKeyInfoDigest?.sha256, true],
      ["DER Parsing Error", parsed.parseError],
    ])}
  </details>`;
}

function render(tab, record) {
  const app = document.querySelector("#app");
  const host = (() => { try { return new URL(tab.url).hostname || tab.url; } catch { return tab.url; } })();

  if (!record) {
    app.innerHTML = `<h1>${html(host)}</h1><p class="empty">No connection data. Reload an HTTP or HTTPS page and open the extension again.</p>`;
    return;
  }
  if (record.error) {
    app.innerHTML = `<h1>${html(host)}</h1><div class="status bad"><strong>Connection failed</strong>${html(record.error)}. Certificate data is unavailable when the TLS handshake fails.</div>`;
    return;
  }

  const info = record.securityInfo;
  const trust = describeTrust(info);
  const certs = info.certificates ?? [];
  const exception = hasCertificateException(info);
  const incompleteChain = exception && certs.length < 2;
  app.innerHTML = `
    <h1>${html(host)}</h1>
    <p class="muted">${html(record.url)}</p>
    <div class="status ${trust.tone}"><strong>${html(trust.title)}</strong>${html(trust.detail)}</div>
    ${incompleteChain ? `<div class="status warn"><strong>Incomplete certificate chain</strong>The WebExtensions API returned only the site certificate because no trusted chain was constructed.</div>` : ""}
    ${certs.length ? `<h2>Certificate chain (${certs.length})</h2><section class="chain">${certs.map((cert, index) => certificate(cert, index, certs.length)).join("")}</section>` : ""}
    <h2>Connection</h2>
    ${rows([
      ["State", info.state],
      ["TLS Version", info.protocolVersion],
      ["Cipher Suite", info.cipherSuite, true],
      ["Key Exchange Group", info.keaGroupName],
      ["Signature Scheme", info.signatureSchemeName],
      ["Secret Key Length", info.secretKeyLength ? `${info.secretKeyLength} bits` : undefined],
      ["HSTS", yesNo(info.hsts)],
      ["Certificate Transparency", info.certificateTransparencyStatus],
      ["OCSP Used", yesNo(info.usedOcsp)],
      ["ECH Used", yesNo(info.usedEch)],
      ["Private DNS", yesNo(info.usedPrivateDns)],
      ["Hostname Mismatch", yesNo(info.isDomainMismatch)],
      ["Outside Validity Period", yesNo(info.isNotValidAtThisTime)],
      ["Extended Validation", yesNo(info.isExtendedValidation)],
      ["Weakness Reason", info.weaknessReasons],
    ])}`;
}

async function main() {
  const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
  if (!tab) return;
  const record = await browser.runtime.sendMessage({ type: "get-security-info", tabId: tab.id });
  render(tab, record);
}

if (typeof document !== "undefined") main().catch((error) => {
  document.querySelector("#app").innerHTML = `<p class="empty">Error: ${html(error.message)}</p>`;
});
