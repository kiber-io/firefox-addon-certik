export const hasCertificateException = (info) =>
  info?.state === "broken" || info?.isUntrusted || info?.isDomainMismatch || info?.isNotValidAtThisTime;

export function connectionIndicator(info) {
  if (!info || info.state === "insecure") return { color: "gray", title: "No TLS certificate" };
  if (info.state === "weak" || hasCertificateException(info)) return { color: "yellow", title: "Certificate exception or weak TLS connection" };
  return { color: "green", title: "Certificate trusted" };
}

export function describeTrust(info) {
  if (!info || info.state === "insecure") {
    return { tone: "bad", title: "No secure TLS connection", detail: "HTTP connections do not have a certificate chain." };
  }
  if (hasCertificateException(info)) {
    const reasons = [
      info.isUntrusted && "no chain to a trusted root",
      info.isDomainMismatch && "certificate hostname mismatch",
      info.isNotValidAtThisTime && "certificate is expired or not yet valid",
    ].filter(Boolean).join("; ");
    return {
      tone: "warn",
      title: "Certificate exception active",
      detail: `${reasons || info.errorMessage || "certificate validation error"}. The certificate remains untrusted. The WebExtensions API does not expose whether the exception is temporary or persistent.`,
    };
  }

  const root = info.certificates?.[info.certificates.length - 1];
  if (root?.isBuiltInRoot) {
    return { tone: info.state === "weak" ? "warn" : "good", title: "Certificate trusted", detail: "The chain terminates at a root in the Mozilla Root Store." };
  }
  return {
    tone: info.state === "weak" ? "warn" : "good",
    title: "Certificate trusted",
    detail: "The root is not built into Firefox. It may come from the Firefox profile, the operating-system trust store, or enterprise policy. The WebExtensions API does not distinguish these sources.",
  };
}
