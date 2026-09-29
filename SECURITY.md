# Security

## Reporting a vulnerability

Email **security@uselinkpilot.com**. Please do not open a public issue for a
security report.

Include what you did, what happened, and what you expected. If it involves
the encryption, a reproducing snippet is worth more than a description.

## What this package does and does not protect

Secret payloads are encrypted in the caller's process with AES-GCM-256. The
key is generated locally, carried in the `#` fragment of the share URL, and
never transmitted. LinkPilot stores ciphertext it holds no key for.

That means:

- **The link is the key.** Anyone who obtains the full share URL, including
  the part after the `#`, can read the secret. Treat the URL as the secret.
- **There is no recovery.** If the share URL is lost, nobody can decrypt the
  payload, including LinkPilot. This is intentional.
- **Metadata is not encrypted.** Timing, expiry, view counts, and for
  attachments the file name, size and type, remain visible to the service.
- **This is browser- and process-level encryption.** It protects against the
  service, its database and its edge. It does not protect against a
  compromised machine at either end.

## Verifying the implementation

The wire format is documented at <https://uselinkpilot.com/developers>.

`packages/sdk/test/crypto.vectors.test.ts` runs committed known-answer vectors
shared with the other implementations of the same format. If this package and
the service ever disagreed about a byte, those tests would fail:

```bash
npm ci && npm run build && npm test
```

## Supported versions

The latest published minor version receives security fixes.
