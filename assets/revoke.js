import { decode } from "./crypto.js";
import { requestJSON, showResult, uuidPattern } from "./common.js";
const button = document.getElementById("revoke-btn");
const result = document.getElementById("result");
let identifier;
let token;
let generation = 0;
function loadLink() {
  generation++;
  const values = new URLSearchParams(location.hash.slice(1));
  identifier = values.get("id");
  token = values.get("token");
  result.replaceChildren();
  result.style.display = "none";
  button.textContent = "Permanently revoke";
  button.disabled = false;
  try {
    if (!uuidPattern.test(identifier || "")) throw new Error();
    decode(token, 32);
  } catch {
    button.disabled = true;
    showResult(result, "Invalid revocation link.", true);
  }
}
button.addEventListener("click", async () => {
  const current = generation;
  button.disabled = true;
  button.textContent = "Revoking...";
  try {
    await requestJSON(`/api/secrets/${identifier}/revoke`, { token });
    if (current !== generation) return;
    token = "";
    history.replaceState(null, "", "/revoke");
    showResult(result, "The secret has been revoked.");
  } catch (error) {
    if (current !== generation) return;
    showResult(result, error.message, true);
    button.disabled = false;
  } finally {
    if (current === generation) button.textContent = "Permanently revoke";
  }
});
window.addEventListener("hashchange", loadLink);
window.addEventListener("pagehide", () => {
  generation++;
  token = "";
});
window.addEventListener("pageshow", (event) => {
  if (event.persisted) loadLink();
});
loadLink();
