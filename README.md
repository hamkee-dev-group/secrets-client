# Secrets client

Browser JavaScript for sharing encrypted text, using native Web Crypto without
third-party cryptography libraries or a build step.

Text is encrypted before upload and decrypted locally. The core/backend is written
in pure Rust and uses SQLite for storage; it receives ciphertext, never the
passphrase or encryption key when using this client.

## Cryptography

- AES-256-GCM with a fresh 96-bit nonce and a 128-bit authentication tag.
- PBKDF2-HMAC-SHA256 with 600,000 iterations and a random salt.
- HKDF-SHA256 separates encryption keys from retrieval credentials.
- Optional generation of random 256-bit passphrases.
- Independent deletion tokens; wrong passphrases do not consume views.

Expiry and view limits are authenticated with the ciphertext. The default view limit is 1; zero
means unlimited retrieval until expiration. The server enforces these limits;
recipients can always keep their own copies.

The files in `assets/` are loaded directly as JavaScript modules by the website.
See [the protocol](PROTOCOL.md) for the wire format and key derivation, and
[security notes](SECURITY.md) for the trust model and limitations.

[MIT licensed](LICENSE).
