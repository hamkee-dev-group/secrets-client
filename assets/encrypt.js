import { generatePassphrase, seal, MAX_TEXT_BYTES } from "./crypto.js";
import {
  requestJSON,
  showResult,
  enableCopy,
  enablePassphraseToggle,
  requireSupport,
} from "./common.js";
const form = document.getElementById("encrypt-form");
requireSupport(document.getElementById("result"));
form.querySelector("fieldset").disabled = false;
const text = document.getElementById("secret-text");
const password = document.getElementById("passphrase");
const views = document.getElementById("max-views");
const expiration = document.getElementById("expiration-time");
const button = document.getElementById("submit-btn");
const result = document.getElementById("result");
const status = document.getElementById("passphrase-status");
password.value = "";
let submitting = false;
let linksShown = false;
const textEncoder = new TextEncoder();
const sizeStatus = document.getElementById("secret-size");
function updateTextSize() {
  const bytes = textEncoder.encode(text.value).length;
  const exceeded = bytes > MAX_TEXT_BYTES;
  const message = exceeded
    ? `Secret exceeds the 64 KiB limit by ${(bytes - MAX_TEXT_BYTES).toLocaleString("en-US")} UTF-8 bytes. Shorten it to continue.`
    : "";
  sizeStatus.textContent = `${bytes.toLocaleString("en-US")} / 65,536 UTF-8 bytes (64 KiB maximum)${message ? `. ${message}` : ""}`;
  sizeStatus.classList.toggle("size-error", exceeded);
  text.setCustomValidity(message);
  text.setAttribute("aria-invalid", String(exceeded));
  button.disabled = submitting || exceeded;
  return !exceeded;
}
text.addEventListener("input", updateTextSize);
updateTextSize();

document.getElementById("generate-passphrase").addEventListener("click", () => {
  password.value = generatePassphrase();
  status.textContent =
    "Save this passphrase before creating the secret. Share it separately from the link.";
});
enablePassphraseToggle(password, document.getElementById("toggle-passphrase"));
enableCopy(
  document.getElementById("copy-passphrase"),
  () => password.value,
  status,
  "Generate or enter a passphrase first.",
);
function updateViewHelp() {
  const count = Number(views.value);
  document.getElementById("max-views-help").textContent =
    views.value === "" || !Number.isInteger(count) || count < 0 || count > 100
      ? "Enter a whole number from 0 to 100."
      : count === 0
        ? "0 (unlimited)"
        : `${count} ${count === 1 ? "view" : "views"}; then deleted.`;
}
views.addEventListener("input", updateViewHelp);
updateViewHelp();

function appendLink(label, path, values, identifier) {
  const url = new URL(path, window.location.origin);
  url.hash = new URLSearchParams(values).toString();
  const title = document.createElement("p");
  title.textContent = label;
  const link = document.createElement("a");
  link.id = identifier;
  link.href = url.href;
  link.textContent = url.href;
  // A new tab keeps this page, and the revocation token that exists only here, intact.
  link.target = "_blank";
  link.rel = "noopener noreferrer";
  const section = document.createElement("section");
  section.className = "link-card";
  if (identifier === "revocation-link") section.classList.add("private-link");
  const copy = document.createElement("button");
  copy.type = "button";
  copy.id = `copy-${identifier}`;
  copy.textContent =
    identifier === "recipient-link"
      ? "Copy share link"
      : "Copy private revocation link";
  const feedback = document.createElement("p");
  feedback.setAttribute("role", "status");
  enableCopy(copy, () => link.href, feedback, "No link available.");
  section.append(title, link, copy, feedback);
  result.append(section);
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (submitting) return;
  if (!updateTextSize()) {
    text.reportValidity();
    return;
  }
  submitting = true;
  button.disabled = true;
  button.textContent = "Encrypting...";
  try {
    const viewCount = Number(views.value);
    if (
      views.value.trim() === "" ||
      !Number.isInteger(viewCount) ||
      viewCount < 0 ||
      viewCount > 100
    )
      throw new Error("Max views must be a whole number from 0 to 100.");
    const lifetimes = new Map([
      ["1h", 3600000],
      ["1", 86400000],
      ["3", 3 * 86400000],
      ["7", 7 * 86400000],
      ["30", 30 * 86400000],
    ]);
    const lifetime = lifetimes.get(expiration.value);
    if (lifetime === undefined)
      throw new Error("Select a valid expiration time.");
    const clock = await requestJSON(
      "/_health",
      undefined,
      "Could not reach the server. Nothing was stored; try again.",
    );
    const sealed = await seal(
      text.value,
      password.value,
      viewCount,
      clock.now + lifetime,
    );
    await requestJSON(
      "/api/secrets",
      sealed.request,
      "Connection interrupted. The secret may have been stored, but its links were lost. Create it again.",
    );
    linksShown = true;
    showResult(result, "Secret encrypted and stored.");
    appendLink(
      "Share this link and send the passphrase separately:",
      "/decrypt",
      { id: sealed.request.envelope.metadata.id },
      "recipient-link",
    );
    appendLink(
      "Keep this revocation link private. It deletes the secret without reading it:",
      "/revoke",
      { id: sealed.request.envelope.metadata.id, token: sealed.deletionToken },
      "revocation-link",
    );
    text.value = "";
    password.value = "";
    status.textContent = "Keep the saved passphrase. It cannot be recovered.";
  } catch (error) {
    showResult(result, error.message, true);
  } finally {
    submitting = false;
    updateTextSize();
    button.textContent = "Encrypt & Store";
  }
});
// Leaving loses the revocation link for good, so ask first while the links are shown.
window.addEventListener("beforeunload", (event) => {
  if (linksShown) event.preventDefault();
});
window.addEventListener("pagehide", () => {
  password.value = "";
  text.value = "";
  result.replaceChildren();
});
