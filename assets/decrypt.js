import { deriveCredentials, open, validateMetadata } from "./crypto.js";
import {
  requestJSON,
  showResult,
  uuidPattern,
  enableCopy,
  enablePassphraseToggle,
  setMasked,
  requireSupport,
} from "./common.js";
const form = document.getElementById("decrypt-form");
requireSupport(document.getElementById("result"));
form.querySelector("fieldset").disabled = false;
const password = document.getElementById("passphrase");
const button = document.getElementById("submit-btn");
const result = document.getElementById("result");
const details = document.getElementById("secret-details");
const copy = document.getElementById("copy-secret");
const copyStatus = document.getElementById("copy-status");
const retry = document.getElementById("retry-status");
const toggle = document.getElementById("toggle-passphrase");
let identifier;
let generation = 0;
let clearTimer;
let plaintext = "";
let metadata;
let revealing = false;
enablePassphraseToggle(password, toggle);
enableCopy(copy, () => plaintext, copyStatus, "No secret to copy.");

function clearSecret() {
  plaintext = "";
  password.value = "";
  copy.hidden = true;
  copyStatus.textContent = "";
  result.replaceChildren();
  result.style.display = "none";
  clearTimeout(clearTimer);
}

async function loadSecret() {
  const current = ++generation;
  clearSecret();
  metadata = undefined;
  form.removeAttribute("aria-busy");
  form.hidden = true;
  retry.hidden = true;
  button.disabled = false;
  button.textContent = "Reveal & Decrypt";
  setMasked(password, true);
  toggle.setAttribute("aria-label", "Show passphrase");
  toggle.title = "Show passphrase";
  toggle.setAttribute("aria-pressed", "false");
  identifier = new URLSearchParams(location.hash.slice(1)).get("id");
  document.querySelector("#uuid-display .uuid-value").textContent =
    uuidPattern.test(identifier || "") ? identifier : "Invalid identifier";
  details.textContent = "";
  if (!uuidPattern.test(identifier || "")) {
    showResult(
      result,
      "Use the complete secret link supplied by the sender.",
      true,
    );
    return;
  }
  details.textContent = "Checking availability...";
  try {
    const status = await requestJSON(
      `/api/secrets/${identifier}/status`,
      undefined,
      "Could not reach the server. No view was used; try again.",
    );
    if (current !== generation) return;
    validateMetadata(status.metadata);
    if (
      status.metadata.id !== identifier ||
      !Number.isInteger(status.remaining_views) ||
      status.remaining_views < 0 ||
      status.remaining_views > status.metadata.max_views ||
      (status.metadata.max_views > 0 && status.remaining_views === 0)
    )
      throw new Error("Invalid secret status.");
    metadata = status.metadata;
    const allowance =
      metadata.max_views === 0
        ? "Unlimited views"
        : `${status.remaining_views} ${status.remaining_views === 1 ? "view" : "views"} remaining at last check`;
    details.textContent = `${allowance}. Expires ${new Date(metadata.expires_at).toLocaleString()}.`;
    form.hidden = false;
  } catch (error) {
    if (current !== generation) return;
    details.textContent = "";
    showResult(result, error.message, true);
    retry.hidden = error.status === 404;
  }
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!metadata || button.disabled) return;
  const current = generation;
  const requestedId = identifier;
  const expectedMetadata = metadata;
  button.disabled = true;
  button.textContent = "Decrypting...";
  form.setAttribute("aria-busy", "true");
  let credentials;
  try {
    credentials = await deriveCredentials(password.value, expectedMetadata);
    if (current !== generation) return;
    revealing = true;
    const envelope = await requestJSON(
      `/api/secrets/${requestedId}/retrieve`,
      { token: credentials.retrievalToken },
      "Connection interrupted. A view may have been used; if the secret no longer opens, ask the sender for a new one.",
    );
    if (current !== generation) return;
    const decoded = await open(envelope, credentials, expectedMetadata);
    if (current !== generation) return;
    plaintext = decoded;
    showResult(result, plaintext);
    form.hidden = true;
    copy.hidden = false;
    clearTimer = setTimeout(() => {
      clearSecret();
      showResult(result, "The displayed secret has been cleared.");
    }, 300000);
  } catch (error) {
    if (current !== generation) return;
    showResult(result, error.message, true);
    if (error.status === 404) form.hidden = true;
  } finally {
    revealing = false;
    if (credentials) credentials.retrievalToken = "";
    if (current === generation) {
      password.value = "";
      button.disabled = false;
      button.textContent = "Reveal & Decrypt";
      form.removeAttribute("aria-busy");
    }
  }
});
retry.addEventListener("click", loadSecret);
window.addEventListener("hashchange", loadSecret);
// The server has used the view before it answers: leaving now would lose the secret unseen.
window.addEventListener("beforeunload", (event) => {
  if (revealing) event.preventDefault();
});
window.addEventListener("pagehide", () => {
  generation++;
  clearSecret();
});
window.addEventListener("pageshow", (event) => {
  if (event.persisted) loadSecret();
});
loadSecret();
