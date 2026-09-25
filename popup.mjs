import { parseCertificate } from "./x509.mjs";
import { describeTrust, hasCertificateException } from "./status.mjs";

const text = (value) => value ?? "—";
const yesNo = (value) => value === undefined ? "—" : value ? "yes" : "no";
const date = (value) => value ? new Date(value).toLocaleString("en-US") : "—";
const dnOids = {
  "1.2.643.100.1": "OGRN",
  "1.2.643.100.3": "SNILS",
  "1.2.643.100.4": "INNLE",
  "1.2.643.100.5": "OGRNIP",
  "1.2.643.3.131.1.1": "INN",
};

function decodeDnValue(hex) {
  const bytes = Uint8Array.from(hex.match(/[\da-f]{2}/gi) ?? [], (part) => Number.parseInt(part, 16));
  if (bytes.length < 2) return `#${hex}`;
  let length = bytes[1];
  let offset = 2;
  if (length & 0x80) {
    const size = length & 0x7f;
    if (!size || bytes.length < offset + size) return `#${hex}`;
    length = 0;
    for (let i = 0; i < size; i += 1) length = length * 256 + bytes[offset++];
  }
  const value = bytes.slice(offset, offset + length);
  if (value.length !== length || ![0x0c, 0x12, 0x13, 0x16].includes(bytes[0])) return `#${hex}`;
  return new TextDecoder().decode(value);
}

export function formatDn(value) {
  return String(text(value)).replace(/OID\.([\d.]+)=#([\da-f]+)/gi,
    (_, oid, hex) => `${dnOids[oid] ?? `OID.${oid}`}=${decodeDnValue(hex)}`);
}

function derBytes(rawDER) {
  if (rawDER instanceof ArrayBuffer) return new Uint8Array(rawDER);
  if (ArrayBuffer.isView(rawDER)) return new Uint8Array(rawDER.buffer, rawDER.byteOffset, rawDER.byteLength);
  return Uint8Array.from(rawDER ?? []);
}

export function toPem(rawDER) {
  const bytes = derBytes(rawDER);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  const base64 = btoa(binary).match(/.{1,64}/g)?.join("\n") ?? "";
  return `-----BEGIN CERTIFICATE-----\n${base64}\n-----END CERTIFICATE-----\n`;
}

function safeFilename(value) {
  return String(value || "certificate").replace(/[^\w.-]+/g, "_").replace(/^\.+/, "") || "certificate";
}

function downloadButton(label, filename, content) {
  const button = element("button", { type: "button", className: "download" }, [label]);
  button.disabled = !content;
  button.addEventListener("click", async () => {
    const url = URL.createObjectURL(new Blob([content], { type: "application/x-pem-file" }));
    try {
      await browser.downloads.download({ url, filename, saveAs: false });
    } catch (error) {
      console.error("Certificate download failed", error);
    } finally {
      setTimeout(() => URL.revokeObjectURL(url), 60_000);
    }
  });
  return button;
}

const dnLabels = {
  CN: "Common Name", O: "Organization", C: "Country", ST: "State/Province",
  L: "Locality", STREET: "Street", OGRN: "OGRN", INN: "INN", INNLE: "INNLE",
  SNILS: "SNILS", OGRNIP: "OGRNIP",
};

function dnFields(value) {
  const fields = [];
  let part = "";
  let quoted = false;
  for (const character of formatDn(value)) {
    if (character === '"') quoted = !quoted;
    if (character === "," && !quoted) {
      if (part) fields.push(part);
      part = "";
    } else part += character;
  }
  if (part) fields.push(part);
  return fields.map((field) => {
    const separator = field.indexOf("=");
    const key = separator < 0 ? field : field.slice(0, separator);
    const value = separator < 0 ? field : field.slice(separator + 1).replace(/^"|"$/g, "");
    return [dnLabels[key] || key, value];
  });
}

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

function group(title, items) {
  return element("section", { className: "certificate-group" }, [
    element("h3", {}, [title]),
    rows(items),
  ]);
}

function alternativeNamesGroup(names = []) {
  const section = element("section", { className: "certificate-group" }, [element("h3", {}, ["Subject Alternative Names"])]);
  if (!names.length) {
    section.append(rows([["Name", undefined]]));
  } else if (names.length === 1) {
    section.append(rows([["Name", names[0]]]));
  } else {
    const more = element("details", { className: "more-values" });
    more.append(
      element("summary", {}, [names[0], element("span", { className: "more-label" }, [`+ ${names.length - 1} more`])]),
      rows(names.slice(1).map((name) => ["Name", name])),
    );
    section.append(more);
  }
  return section;
}

function certificate(cert, index, total) {
  const role = index === 0 ? "site certificate" : index === total - 1 ? "chain anchor" : "intermediate CA";
  let parsed = {};
  try { parsed = cert.rawDER ? parseCertificate(cert.rawDER) : {}; } catch (error) { parsed.parseError = error.message; }
  const list = (values) => values?.length ? values.join("; ") : undefined;
  const subject = dnFields(cert.subject);
  const issuer = dnFields(cert.issuer);
  const commonName = subject.find(([label]) => label === "Common Name")?.[1] || formatDn(cert.subject);
  const details = element("details", { open: index === 0 });
  details.append(
    element("summary", {}, [`${index + 1}. ${commonName} `, element("span", { className: "pill" }, [role])]),
    element("div", { className: "certificate-actions" }, [downloadButton("Download PEM", `${safeFilename(commonName)}.pem`, cert.rawDER ? toPem(cert.rawDER) : "")]),
    group("Subject Name", subject),
    group("Issuer Name", issuer),
    group("Validity", [
      ["Not Before", date(cert.validity?.start)],
      ["Not After", date(cert.validity?.end)],
    ]),
    alternativeNamesGroup(parsed.alternativeNames),
    group("Public Key Info", [
      ["Algorithm", parsed.publicKeyAlgorithm],
    ]),
    group("Miscellaneous", [
      ["Serial Number", cert.serialNumber, true],
      ["Signature Algorithm", parsed.signatureAlgorithm],
      ["X.509 Version", parsed.version ? `v${parsed.version}` : undefined],
      ["Certificate Authority", yesNo(parsed.isCA)],
      ["Path Length Constraint", parsed.pathLength],
      ["Built-in Root", yesNo(cert.isBuiltInRoot)],
      ["Subject (raw)", cert.subject],
      ["Issuer (raw)", cert.issuer],
      ["SHA-256", cert.fingerprint?.sha256, true],
      ["SHA-1", cert.fingerprint?.sha1, true],
      ["Public Key SHA-256", cert.subjectPublicKeyInfoDigest?.sha256, true],
      ["Key Usage", list(parsed.keyUsage)],
      ["Extended Key Usage", list(parsed.extendedKeyUsage)],
      ["Certificate Policies", list(parsed.policies)],
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
    app.append(statusBox("warn", "Incomplete certificate chain", certs.length
      ? "The WebExtensions API returned only the site certificate because no trusted chain was constructed."
      : "Firefox did not expose certificate objects for this certificate exception."));
  }
  if (certs.length) {
    const chainPem = certs.filter((cert) => cert.rawDER).map((cert) => toPem(cert.rawDER)).join("\n");
    app.append(
      element("div", { className: "chain-heading" }, [
        element("h2", {}, [`Certificate chain (${certs.length})`]),
        downloadButton("Download chain (PEM)", `${safeFilename(host)}-chain.pem`, chainPem),
      ]),
    );
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
