export const MAX_TEXT_BYTES = 65536;
export const PASSWORD_ITERATIONS = 600000;
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const uuidPattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export function encode(bytes) {
  let value = "";
  for (const byte of bytes) value += String.fromCharCode(byte);
  return btoa(value)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

export function decode(value, minimum, maximum = minimum) {
  if (
    typeof value !== "string" ||
    value.length > Math.ceil(maximum / 3) * 4 ||
    !/^[A-Za-z0-9_-]+$/.test(value)
  )
    throw new Error("Invalid encoded value.");
  const bytes = Uint8Array.from(
    atob(value.replaceAll("-", "+").replaceAll("_", "/")),
    (character) => character.charCodeAt(0),
  );
  if (
    bytes.length < minimum ||
    bytes.length > maximum ||
    encode(bytes) !== value
  )
    throw new Error("Invalid encoded value.");
  return bytes;
}

export function generatePassphrase() {
  return encode(crypto.getRandomValues(new Uint8Array(32)));
}

export function validatePassphrase(passphrase) {
  if (typeof passphrase !== "string" || passphrase.length === 0) {
    throw new Error("Enter a passphrase.");
  }
}

export function validateMetadata(metadata) {
  const fields = ["expires_at", "id", "max_views", "nonce", "salt", "version"];
  if (
    !metadata ||
    Object.keys(metadata).sort().join(",") !== fields.join(",") ||
    metadata.version !== 1 ||
    !uuidPattern.test(metadata.id) ||
    !Number.isSafeInteger(metadata.expires_at) ||
    metadata.expires_at < 0 ||
    !Number.isInteger(metadata.max_views) ||
    metadata.max_views < 0 ||
    metadata.max_views > 100
  ) {
    throw new Error("Invalid secret metadata.");
  }
  decode(metadata.salt, 16);
  decode(metadata.nonce, 12);
}

export function authenticatedData(metadata) {
  validateMetadata(metadata);
  return encoder.encode(
    [
      "srs-browser-1",
      metadata.id,
      metadata.expires_at,
      metadata.max_views,
      metadata.salt,
      metadata.nonce,
    ].join("\n"),
  );
}

async function deriveBytes(master, salt, id, purpose) {
  return new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt,
        info: encoder.encode(`srs-browser-1/${id}/${purpose}`),
      },
      master,
      256,
    ),
  );
}

export async function deriveCredentials(passphrase, metadata) {
  validatePassphrase(passphrase);
  validateMetadata(metadata);
  const password = encoder.encode(passphrase);
  const salt = decode(metadata.salt, 16);
  let material;
  try {
    const input = await crypto.subtle.importKey(
      "raw",
      password,
      "PBKDF2",
      false,
      ["deriveBits"],
    );
    material = new Uint8Array(
      await crypto.subtle.deriveBits(
        {
          name: "PBKDF2",
          hash: "SHA-256",
          salt,
          iterations: PASSWORD_ITERATIONS,
        },
        input,
        256,
      ),
    );
    const master = await crypto.subtle.importKey(
      "raw",
      material,
      "HKDF",
      false,
      ["deriveBits"],
    );
    const encryptionBytes = await deriveBytes(
      master,
      salt,
      metadata.id,
      "encryption",
    );
    const retrievalBytes = await deriveBytes(
      master,
      salt,
      metadata.id,
      "retrieval",
    );
    try {
      const encryptionKey = await crypto.subtle.importKey(
        "raw",
        encryptionBytes,
        "AES-GCM",
        false,
        ["encrypt", "decrypt"],
      );
      return { encryptionKey, retrievalToken: encode(retrievalBytes) };
    } finally {
      encryptionBytes.fill(0);
      retrievalBytes.fill(0);
    }
  } finally {
    password.fill(0);
    material?.fill(0);
  }
}

export async function hashToken(token) {
  const bytes = decode(token, 32);
  try {
    return encode(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)));
  } finally {
    bytes.fill(0);
  }
}

export async function seal(text, passphrase, maxViews, expiresAt) {
  if (typeof text !== "string") throw new Error("Invalid secret text.");
  const plaintext = encoder.encode(text);
  if (plaintext.length < 1 || plaintext.length > MAX_TEXT_BYTES)
    throw new Error("Secret must contain 1–65536 UTF-8 bytes.");
  const metadata = {
    version: 1,
    id: crypto.randomUUID(),
    expires_at: expiresAt,
    max_views: maxViews,
    salt: encode(crypto.getRandomValues(new Uint8Array(16))),
    nonce: encode(crypto.getRandomValues(new Uint8Array(12))),
  };
  let credentials;
  try {
    credentials = await deriveCredentials(passphrase, metadata);
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv: decode(metadata.nonce, 12),
          additionalData: authenticatedData(metadata),
          tagLength: 128,
        },
        credentials.encryptionKey,
        plaintext,
      ),
    );
    const deletionToken = generatePassphrase();
    return {
      request: {
        envelope: { metadata, ciphertext: encode(ciphertext) },
        retrieval_hash: await hashToken(credentials.retrievalToken),
        deletion_hash: await hashToken(deletionToken),
      },
      deletionToken,
    };
  } finally {
    plaintext.fill(0);
    if (credentials) credentials.retrievalToken = "";
  }
}

export async function open(envelope, credentials, expectedMetadata) {
  const actual = authenticatedData(envelope.metadata);
  const expected = authenticatedData(expectedMetadata);
  if (encode(actual) !== encode(expected))
    throw new Error("Secret metadata changed.");
  const ciphertext = decode(envelope.ciphertext, 17, MAX_TEXT_BYTES + 16);
  let plaintext;
  try {
    plaintext = new Uint8Array(
      await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: decode(envelope.metadata.nonce, 12),
          additionalData: actual,
          tagLength: 128,
        },
        credentials.encryptionKey,
        ciphertext,
      ),
    );
    return decoder.decode(plaintext);
  } catch {
    throw new Error(
      "The secret could not be authenticated. A retrieval may already have consumed a view.",
    );
  } finally {
    plaintext?.fill(0);
  }
}
