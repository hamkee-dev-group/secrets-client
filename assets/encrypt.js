import { generatePassphrase, seal, MAX_TEXT_BYTES } from "./crypto.js";
import {
  requestJSON,
  showResult,
  enableCopy,
  enablePassphraseToggle,
  isMasked,
  setMasked,
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
const noPassphrase = document.getElementById("no-passphrase");
const copyPassphrase = document.getElementById("copy-passphrase");
const togglePassphrase = document.getElementById("toggle-passphrase");
function updatePassphraseMode() {
  password.disabled = noPassphrase.checked;
  password.required = !noPassphrase.checked;
  copyPassphrase.disabled = noPassphrase.checked || !password.value;
  togglePassphrase.disabled = noPassphrase.checked;
}
noPassphrase.addEventListener("change", () => {
  status.textContent = noPassphrase.checked
    ? "Anyone with the complete share link can read the secret."
    : "12 characters or more is recommended.";
  updatePassphraseMode();
});
password.addEventListener("input", () => {
  if (password.value) noPassphrase.checked = false;
  updatePassphraseMode();
});
updatePassphraseMode();
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
  noPassphrase.checked = false;
  password.value = generatePassphrase();
  updatePassphraseMode();
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

// One card of the share view: a label, the value (a link, or the masked passphrase) and its
// Copy button. Copy feedback shows on the button; the status line is for screen readers.
function shareCard(label, identifier, copyLabel, { href, secret }) {
  const section = document.createElement("section");
  section.className = "link-card";
  const title = document.createElement("p");
  title.textContent = label;
  let field;
  if (href) {
    field = document.createElement("a");
    field.href = href;
    field.textContent = href;
    // A new tab keeps this page, and the revocation token that exists only here, intact.
    field.target = "_blank";
    field.rel = "noopener noreferrer";
  } else {
    field = document.createElement("input");
    setMasked(field, true);
    field.readOnly = true;
    field.value = secret;
    field.autocomplete = "off";
    field.spellcheck = false;
    field.setAttribute("aria-label", label);
  }
  field.id = identifier;
  const buttons = document.createElement("div");
  buttons.className = "actions";
  const copy = document.createElement("button");
  copy.type = "button";
  copy.id = `copy-${identifier}`;
  copy.textContent = copyLabel;
  const feedback = document.createElement("p");
  feedback.className = "visually-hidden";
  feedback.setAttribute("role", "status");
  enableCopy(copy, () => href || field.value, feedback, "Nothing to copy.");
  if (!href) {
    const show = document.createElement("button");
    show.type = "button";
    show.id = `show-${identifier}`;
    show.textContent = "Show";
    show.setAttribute("aria-pressed", "false");
    show.addEventListener("click", () => {
      const visible = isMasked(field);
      setMasked(field, !visible);
      show.textContent = visible ? "Hide" : "Show";
      show.setAttribute("aria-pressed", String(visible));
    });
    buttons.append(show);
  }
  buttons.append(copy);
  section.append(title, field, buttons, feedback);
  return section;
}

function shareLink(path, values) {
  const url = new URL(path, window.location.origin);
  url.hash = new URLSearchParams(values).toString();
  return url.href;
}

// Back to an empty form for the next secret.
function startOver() {
  linksShown = false;
  result.replaceChildren();
  result.className = "";
  result.style.display = "none";
  result.style.minHeight = "";
  form.hidden = false;
  noPassphrase.checked = false;
  updatePassphraseMode();
  status.textContent = "12 characters or more is recommended.";
  text.focus();
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (submitting) return;
  if (!updateTextSize()) {
    text.reportValidity();
    return;
  }
  const linkOnly = noPassphrase.checked;
  const encryptionSecret = linkOnly ? generatePassphrase() : password.value;
  const message = text.value;
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
      message,
      encryptionSecret,
      viewCount,
      clock.now + lifetime,
    );
    await requestJSON(
      "/api/secrets",
      sealed.request,
      "Connection interrupted. The secret may have been stored, but its links were lost. Create it again.",
    );
    linksShown = true;
    // Replace the form with the share view, keeping the box the same height. The passphrase
    // stays available here, so copying the link first can no longer lose it.
    const height = form.offsetHeight;
    const id = sealed.request.envelope.metadata.id;
    showResult(
      result,
      linkOnly
        ? "Secret encrypted. Anyone with the complete share link can read it."
        : "Secret encrypted. Send the link and the passphrase separately.",
    );
    const again = document.createElement("button");
    again.type = "button";
    again.id = "new-secret";
    again.className = "submit-btn";
    again.textContent = "Create another secret";
    again.addEventListener("click", startOver);
    const management = shareCard(
      "Management link: keep it private. View activity or revoke access.",
      "management-link",
      "Copy management link",
      { href: shareLink("/manage", { id, token: sealed.deletionToken }) },
    );
    management.classList.add("private-link");
    if (!linkOnly) result.append(shareCard("Passphrase:", "shared-passphrase", "Copy passphrase", {
      secret: encryptionSecret,
    }));
    result.append(
      shareCard("Share link:", "recipient-link", "Copy share link", {
        href: shareLink("/decrypt", linkOnly ? { id, key: encryptionSecret } : { id }),
      }),
      management,
      again,
    );
    form.hidden = true;
    result.style.minHeight = `${height}px`;
    text.value = "";
    password.value = "";
    updatePassphraseMode();
    status.textContent = "Keep the saved passphrase. It cannot be recovered.";
  } catch (error) {
    showResult(result, error.message, true);
  } finally {
    submitting = false;
    updateTextSize();
    button.textContent = "Encrypt & Share";
  }
});
// Leaving loses the revocation link for good, so ask first while the links are shown.
window.addEventListener("beforeunload", (event) => {
  if (linksShown) event.preventDefault();
});
window.addEventListener("pagehide", () => {
  password.value = "";
  text.value = "";
  linksShown = false;
  result.replaceChildren();
  result.style.display = "none";
  result.style.minHeight = "";
  form.hidden = false;
});
