# Security

The client keeps plaintext, passphrases and AES keys out of API requests. It sends
ciphertext, public metadata and retrieval or deletion credentials. The server
stores hashes of those credentials. A stolen database can still be used to guess
weak passphrases offline; PBKDF2 is not memory-hard.

AES-GCM authenticates the ciphertext and immutable metadata. Encryption and retrieval
keys have distinct HKDF purpose labels. Deletion uses an independent random token.
The exact encoding and derivation are documented in [PROTOCOL.md](PROTOCOL.md).

The website and browser must be trusted while entering a secret. An attacker who
can replace the JavaScript, compromise the browser or read the clipboard can steal
inputs. Downloading and reviewing a local client reduces dependence on website
updates, but does not secure a compromised computer.

Retrieval authorization consumes a view before delivery. A lost response or damaged
ciphertext can therefore cost a view even when decryption fails. Requests are not
automatically retried. Neither expiry nor deletion can erase a recipient's copies.

Temporary byte arrays are overwritten where practical. JavaScript strings and
browser internals cannot be reliably wiped. Non-extractable keys do not prevent
malicious JavaScript from using them.

Report vulnerabilities privately to hello@hamkee.net rather than posting secret
material or an exploit in a public issue.
