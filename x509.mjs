const OIDS = {
  "1.2.840.113549.1.1.1": "RSA",
  "1.2.840.113549.1.1.5": "SHA-1 with RSA",
  "1.2.840.113549.1.1.10": "RSA-PSS",
  "1.2.840.113549.1.1.11": "SHA-256 with RSA",
  "1.2.840.113549.1.1.12": "SHA-384 with RSA",
  "1.2.840.113549.1.1.13": "SHA-512 with RSA",
  "1.2.840.10045.2.1": "EC",
  "1.2.840.10045.3.1.7": "P-256",
  "1.3.132.0.34": "P-384",
  "1.3.132.0.35": "P-521",
  "1.2.840.10045.4.3.2": "ECDSA with SHA-256",
  "1.2.840.10045.4.3.3": "ECDSA with SHA-384",
  "1.2.840.10045.4.3.4": "ECDSA with SHA-512",
  "1.3.101.112": "Ed25519",
};

const EKU = {
  "1.3.6.1.5.5.7.3.1": "TLS Web Server Authentication",
  "1.3.6.1.5.5.7.3.2": "TLS Web Client Authentication",
  "1.3.6.1.5.5.7.3.3": "Code Signing",
  "1.3.6.1.5.5.7.3.4": "Email Protection",
  "1.3.6.1.5.5.7.3.8": "Time Stamping",
  "1.3.6.1.5.5.7.3.9": "OCSP Signing",
};

function node(bytes, offset = 0) {
  const tag = bytes[offset++];
  if (tag === undefined) throw new Error("Unexpected end of DER data");
  let length = bytes[offset++];
  if (length & 0x80) {
    const count = length & 0x7f;
    if (!count || count > 4) throw new Error("Unsupported DER length");
    length = 0;
    for (let i = 0; i < count; i++) length = length * 256 + bytes[offset++];
  }
  const start = offset;
  const end = start + length;
  if (end > bytes.length) throw new Error("Invalid DER data");
  const children = [];
  if (tag & 0x20) {
    while (offset < end) {
      const child = node(bytes, offset);
      children.push(child);
      offset = child.end;
    }
  }
  return { tag, start, end, children };
}

function oid(bytes, item) {
  const values = [];
  let value = 0;
  for (let i = item.start; i < item.end; i++) {
    value = value * 128 + (bytes[i] & 0x7f);
    if (!(bytes[i] & 0x80)) {
      values.push(value);
      value = 0;
    }
  }
  const first = Math.min(2, Math.floor(values[0] / 40));
  return [first, values[0] - first * 40, ...values.slice(1)].join(".");
}

const algorithm = (bytes, item) => {
  const id = oid(bytes, item.children[0]);
  const parameter = item.children[1]?.tag === 6 ? oid(bytes, item.children[1]) : null;
  return `${OIDS[id] || id}${parameter ? ` (${OIDS[parameter] || parameter})` : ""}`;
};

const integer = (bytes, item) => {
  let value = 0;
  for (let i = item.start; i < item.end; i++) value = value * 256 + bytes[i];
  return value;
};

const ascii = (bytes, item) => new TextDecoder("ascii").decode(bytes.slice(item.start, item.end));
const ip = (bytes) => bytes.length === 4
  ? [...bytes].join(".")
  : Array.from({ length: bytes.length / 2 }, (_, i) => ((bytes[i * 2] << 8) | bytes[i * 2 + 1]).toString(16)).join(":");

export function parseCertificate(rawDER) {
  const bytes = Uint8Array.from(rawDER);
  const certificate = node(bytes);
  const tbs = certificate.children[0];
  let i = tbs.children[0]?.tag === 0xa0 ? 1 : 0;
  const version = i ? integer(bytes, tbs.children[0].children[0]) + 1 : 1;
  const publicKey = tbs.children[i + 5];
  const result = {
    version,
    signatureAlgorithm: algorithm(bytes, certificate.children[1]),
    publicKeyAlgorithm: algorithm(bytes, publicKey.children[0]),
    alternativeNames: [],
    keyUsage: [],
    extendedKeyUsage: [],
    policies: [],
  };

  const wrapper = tbs.children.find((child) => child.tag === 0xa3);
  for (const extension of wrapper?.children[0]?.children || []) {
    const id = oid(bytes, extension.children[0]);
    const value = extension.children.at(-1);
    const inner = node(bytes, value.start);

    if (id === "2.5.29.17") {
      const labels = { 0x81: "Email", 0x82: "DNS", 0x86: "URI" };
      result.alternativeNames = inner.children.map((name) =>
        name.tag === 0x87 ? `IP: ${ip(bytes.slice(name.start, name.end))}` : `${labels[name.tag] || "Other"}: ${ascii(bytes, name)}`
      );
    } else if (id === "2.5.29.15") {
      const names = ["Digital Signature", "Non Repudiation", "Key Encipherment", "Data Encipherment", "Key Agreement", "Certificate Signing", "CRL Signing", "Encipher Only", "Decipher Only"];
      const bits = bytes.slice(inner.start + 1, inner.end);
      result.keyUsage = names.filter((_, bit) => bits[Math.floor(bit / 8)] & (0x80 >> (bit % 8)));
    } else if (id === "2.5.29.37") {
      result.extendedKeyUsage = inner.children.map((purpose) => {
        const purposeId = oid(bytes, purpose);
        return EKU[purposeId] || purposeId;
      });
    } else if (id === "2.5.29.19") {
      result.isCA = inner.children[0]?.tag === 1 && bytes[inner.children[0].start] !== 0;
      const pathLength = inner.children.find((child) => child.tag === 2);
      if (pathLength) result.pathLength = integer(bytes, pathLength);
    } else if (id === "2.5.29.32") {
      result.policies = inner.children.map((policy) => oid(bytes, policy.children[0]));
    }
  }
  return result;
}
