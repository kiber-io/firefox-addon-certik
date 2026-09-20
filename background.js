import { connectionIndicator } from "./status.mjs";

const key = (tabId) => `tab-${tabId}`;
const save = (tabId, record) => browser.storage.session.set({ [key(tabId)]: record });
const read = async (tabId) => (await browser.storage.session.get(key(tabId)))[key(tabId)] ?? null;
const forget = (tabId) => browser.storage.session.remove(key(tabId));
const setIndicator = (tabId, color, title) => {
  browser.action.setIcon({ tabId, path: `icon-${color}.svg` }).catch(() => {});
  browser.action.setTitle({ tabId, title }).catch(() => {});
};
const restoreIndicator = async (tabId) => {
  const record = await read(tabId);
  if (!record) return setIndicator(tabId, "gray", "No certificate data");
  if (record.error) return setIndicator(tabId, "red", "Connection error");
  const indicator = connectionIndicator(record.securityInfo);
  setIndicator(tabId, indicator.color, indicator.title);
};

browser.webRequest.onBeforeRequest.addListener(
  ({ tabId }) => {
    forget(tabId);
    if (tabId >= 0) setIndicator(tabId, "gray", "Certificate data pending");
  },
  { urls: ["<all_urls>"], types: ["main_frame"] },
);

browser.webRequest.onHeadersReceived.addListener(
  async ({ requestId, tabId, url }) => {
    if (tabId < 0) return;

    try {
      const securityInfo = await browser.webRequest.getSecurityInfo(requestId, {
        certificateChain: true,
        rawDER: true,
      });
      await save(tabId, { url, capturedAt: Date.now(), securityInfo });
      const indicator = connectionIndicator(securityInfo);
      setIndicator(tabId, indicator.color, indicator.title);
    } catch (error) {
      await save(tabId, { url, error: error.message });
      setIndicator(tabId, "red", "TLS connection error");
    }
  },
  { urls: ["<all_urls>"], types: ["main_frame"] },
  ["blocking"],
);

browser.webRequest.onErrorOccurred.addListener(
  ({ tabId, url, error }) => {
    if (tabId >= 0) {
      save(tabId, { url, error });
      setIndicator(tabId, "red", "Connection error");
    }
  },
  { urls: ["<all_urls>"], types: ["main_frame"] },
);

browser.runtime.onMessage.addListener(async ({ type, tabId }) => {
  if (type !== "get-security-info") return undefined;
  return read(tabId);
});

browser.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === "complete") restoreIndicator(tabId);
});
browser.tabs.onActivated.addListener(({ tabId }) => restoreIndicator(tabId));
browser.tabs.onRemoved.addListener(forget);
browser.tabs.onReplaced.addListener((_, removedTabId) => forget(removedTabId));
