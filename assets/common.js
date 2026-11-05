export const uuidPattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export function showResult(element, message, isError = false) {
  element.textContent = message;
  element.className = isError ? "error" : "success";
  element.style.display = "block";
}

export async function requestJSON(path, payload) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 15000);
  try {
    const response = await fetch(path, {
      method: payload === undefined ? "GET" : "POST",
      headers:
        payload === undefined ? {} : { "Content-Type": "application/json" },
      body: payload === undefined ? undefined : JSON.stringify(payload),
      cache: "no-store",
      credentials: "omit",
      referrerPolicy: "no-referrer",
      redirect: "error",
      signal: controller.signal,
    });
    const body = await response.text();
    let data;
    try {
      data = body ? JSON.parse(body) : {};
    } catch {
      throw new Error("Invalid server response.");
    }
    if (!response.ok) {
      const error = new Error(
        typeof data.error === "string"
          ? data.error
          : `Request failed (${response.status}).`,
      );
      error.status = response.status;
      throw error;
    }
    return data;
  } catch (error) {
    if (error.name === "AbortError" || error instanceof TypeError)
      throw new Error(
        "Connection interrupted. The operation may have completed; a retrieval may have consumed a view.",
      );
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

export function enablePassphraseToggle(input, button) {
  button.addEventListener("click", () => {
    const visible = input.type === "password";
    input.type = visible ? "text" : "password";
    const label = visible ? "Hide passphrase" : "Show passphrase";
    button.setAttribute("aria-label", label);
    button.title = label;
    button.setAttribute("aria-pressed", String(visible));
  });
}

export function enableCopy(button, value, status, emptyMessage) {
  button.addEventListener("click", async () => {
    const text = value();
    if (!text) {
      status.textContent = emptyMessage;
      return;
    }
    try {
      await navigator.clipboard.writeText(text);
      status.textContent = "Copied.";
    } catch {
      status.textContent =
        "Copy unavailable. Select the text and copy it manually.";
    }
  });
}
