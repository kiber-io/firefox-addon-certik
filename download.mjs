const params = new URLSearchParams(location.search);
const id = params.get("id");
const key = `download-${id}`;
const record = id && (await browser.storage.session.get(key))[key];
const filename = document.querySelector("#filename");
const link = document.querySelector("#download");
const status = document.querySelector("#status");

if (record) {
  const url = URL.createObjectURL(new Blob([record.content], { type: "application/x-pem-file" }));
  filename.textContent = record.filename;
  link.href = url;
  link.download = record.filename;
  link.hidden = false;
  status.textContent = "If the download did not start, tap the button.";
  setTimeout(() => link.click(), 1200);
  await browser.storage.session.remove(key);
} else {
  filename.textContent = "Unavailable";
  status.textContent = "Download data is unavailable.";
}
