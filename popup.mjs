import { parseCertificate } from "./x509.mjs";
import { describeTrust, hasCertificateException } from "./status.mjs";

const text = (value) => value ?? "—";
const yesNo = (value) => value === undefined ? "—" : value ? "yes" : "no";
const date = (value) => value ? new Date(value).toLocaleString("en-US") : "—";

function element(tag, properties = {}, children = []) {
  const node = document.createElement(tag);
  for (const [name, value] of Object.entries(properties)) {
    if (name === "className") node.className = value;
    else if (name === "open") node.open = value;
    else node.setAttribute(name, value);
  }
  node.append(...children);
  return node;
}

function rows(items) {
  const dl = element("dl", { className: "grid" });
  for (const [label, value, code = false] of items) {
    const dd = element("dd");
    dd.append(code ? element("code", {}, [String(text(value))]) : String(text(value)));
    dl.append(element("dt", { className: "label" }, [label]), dd);
  }
  return dl;
}

function certificate(cert, index, total) {
  const role = index === 0 ? "site certificate" : index === total - 1 ? "chain anchor" : "intermediate CA";
  let parsed = {};
  try { parsed = cert.rawDER ? parseCertificate(cert.rawDER) : {}; } catch (error) { parsed.parseError = error.message; }
  const list = (values) => values?.length ? values.join("; ") : undefined;
  const details = element("details", { open: index === 0 });
  details.append(
    element("summary", {}, [`${index + 1}. ${text(cert.subject)} `, element("span", { className: "pill" }, [role])]),
    rows([
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
    ]),
  );
  return details;
}

function statusBox(className, title, detail) {
  return element("div", { className: `status ${className}` }, [
    element("strong", {}, [title]),
    detail,
  ]);
}

function render(tab, record) {
  const app = document.querySelector("#app");
  const host = (() => { try { return new URL(tab.url).hostname || tab.url; } catch { return tab.url; } })();
  app.replaceChildren(element("h1", {}, [text(host)]));

  if (!record) {
    app.append(element("p", { className: "empty" }, ["No connection data. Reload an HTTP or HTTPS page and open the extension again."]));
    return;
  }
  if (record.error) {
    app.append(statusBox("bad", "Connection failed", `${record.error}. Certificate data is unavailable when the TLS handshake fails.`));
    return;
  }

  const info = record.securityInfo;
  const trust = describeTrust(info);
  const certs = info.certificates ?? [];
  app.append(element("p", { className: "muted" }, [text(record.url)]), statusBox(trust.tone, trust.title, trust.detail));

  const exception = hasCertificateException(info);
  if (exception && certs.length < 2) {
    app.append(statusBox("warn", "Incomplete certificate chain", "The WebExtensions API returned only the site certificate because no trusted chain was constructed."));
  }
  if (certs.length) {
    app.append(element("h2", {}, [`Certificate chain (${certs.length})`]));
    app.append(element("section", { className: "chain" }, certs.map((cert, index) => certificate(cert, index, certs.length))));
  }

  app.append(
    element("h2", {}, ["Connection"]),
    rows([
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
    ]),
  );
}

async function main() {
  const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
  if (!tab) return;
  const record = await browser.runtime.sendMessage({ type: "get-security-info", tabId: tab.id });
  render(tab, record);
}

if (typeof document !== "undefined") main().catch((error) => {
  const app = document.querySelector("#app");
  app.replaceChildren(element("p", { className: "empty" }, [`Error: ${error.message}`]));
});
