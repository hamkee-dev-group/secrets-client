import { decode } from "./crypto.js";
import { requestJSON, requireSupport, showResult, uuidPattern } from "./common.js";
const button = document.getElementById("revoke-btn");
const refresh = document.getElementById("refresh-receipt");
const receipt = document.getElementById("receipt");
const result = document.getElementById("result");
requireSupport(result);
let identifier;
let token;
let generation = 0;
const date = value => value == null ? "Not recorded" : new Date(value).toLocaleString();
function line(text) {
  const node = document.createElement("p");
  node.textContent = text;
  receipt.append(node);
}
async function loadReceipt() {
  const current = ++generation;
  const values = new URLSearchParams(location.hash.slice(1));
  identifier = values.get("id");
  token = values.get("token");
  button.disabled = true;
  button.hidden = true;
  refresh.disabled = true;
  receipt.replaceChildren();
  result.style.display = "none";
  try {
    if (!uuidPattern.test(identifier || "")) throw new Error("Invalid management link.");
    try { decode(token, 32); } catch { throw new Error("Invalid management link."); }
    const data = await requestJSON(`/api/secrets/${identifier}/management`, { token });
    if (current !== generation) return;
    const labels = { active: "Active", consumed: "Fully consumed", revoked: "Revoked", expired: "Expired" };
    if (!Object.hasOwn(labels, data.status)) throw new Error("Invalid receipt status.");
    line(`${labels[data.status]}${data.ended_at == null ? "" : ` · ${date(data.ended_at)}`}`);
    const used = `${data.views_used} ${data.views_used === 1 ? "view" : "views"} used`;
    line(data.max_views === 0
      ? `${used}${data.status === "active" ? " · Unlimited until expiration" : ""}`
      : `${data.views_used} of ${data.max_views} views used${data.status === "active" ? ` · ${data.max_views - data.views_used} remaining` : ""}`);
    if (data.views_used > 0) line(`Last accessed: ${date(data.last_accessed_at)}`);
    line(`${data.failed_attempts} unsuccessful access ${data.failed_attempts === 1 ? "attempt" : "attempts"}${data.last_failed_at == null ? "" : ` · Last: ${date(data.last_failed_at)}`}`);
    line(`Secret expiration: ${date(data.expires_at)}`);
    line(`Receipt kept until: ${date(data.receipt_expires_at)}`);
    line("Views count authorized retrievals, not confirmed reading. Failed attempts exclude rate-limited requests.");
    button.disabled = data.status !== "active";
    button.hidden = data.status !== "active";
  } catch (error) {
    if (current !== generation) return;
    showResult(result, error.status === 404 ? "Management receipt unavailable or expired." : error.message, true);
  } finally {
    if (current === generation) refresh.disabled = false;
  }
}
button.addEventListener("click", async () => {
  if (button.disabled || !window.confirm("Permanently revoke this secret? This cannot be undone.")) return;
  const current = generation;
  button.disabled = true;
  button.textContent = "Revoking…";
  try {
    await requestJSON(`/api/secrets/${identifier}/revoke`, { token });
    if (current !== generation) return;
    await loadReceipt();
  } catch (error) {
    if (current !== generation) return;
    await loadReceipt();
    showResult(result, error.message, true);
  } finally {
    button.textContent = "Permanently revoke";
  }
});
refresh.addEventListener("click", loadReceipt);
window.addEventListener("hashchange", loadReceipt);
window.addEventListener("pagehide", () => {
  generation++;
  token = "";
  receipt.replaceChildren();
});
window.addEventListener("pageshow", event => {
  if (event.persisted) loadReceipt();
});
loadReceipt();
