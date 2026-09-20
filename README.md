# Certificate Chain Inspector

Firefox Manifest V3 extension that displays TLS connection parameters and the certificate chain for the active tab.

The toolbar icon is green for a trusted certificate, yellow for a certificate exception or weak TLS connection, red for a connection error, and gray when no TLS certificate is available.

## Run

1. Open `about:debugging#/runtime/this-firefox`.
2. Select **Load Temporary Add-on** and choose `manifest.json`.
3. Open or reload an HTTP or HTTPS page.
4. Open the extension from the toolbar.

Alternatively, run `web-ext run`.

## Test

```sh
node test.mjs
```

The extension does not collect or transmit data. Tab data is retained only in `storage.session`.

The WebExtensions API identifies roots from the Mozilla Root Store. It does not distinguish roots imported into the Firefox profile from operating-system or enterprise-policy roots.

For connections using a certificate exception, the API may return only the site certificate because no trusted chain was constructed.
