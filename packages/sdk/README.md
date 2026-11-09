# @uselinkpilot/sdk

Typed client for the [LinkPilot](https://uselinkpilot.com) API v1.

```bash
npm install @uselinkpilot/sdk
```

## Secrets are encrypted in your process

This is the part that differs from most API clients. LinkPilot's API **will
not accept a plaintext secret**: it takes ciphertext and an `enc_version`, and
rejects a `payload` field outright. LinkPilot never receives the decryption
key and cannot read what it stores.

So the SDK encrypts locally with AES-GCM-256, sends only the ciphertext, and
stitches the key onto the returned URL for you:

```ts
import { LinkPilot } from "@uselinkpilot/sdk";

const lp = new LinkPilot({ apiKey: process.env.LINKPILOT_API_KEY });

const secret = await lp.secrets.create({
  secret: "db password: hunter2",
  ttlSeconds: 3600,
});

console.log(secret.shareUrl);
// https://shrd.link/s/abcdefghij#k=<key>
```

**Send `shareUrl`, not `secretUrl`.** The part after the `#` is the key.
Browsers never transmit it, which is why LinkPilot cannot see it. A URL
without that fragment opens nothing, for anyone, including us. There is no
recovery path: lose the share URL and the secret is gone.

A passphrase is a real second factor, not a label. It is stretched with
PBKDF2-SHA256 and folded into the key, so neither the link alone nor the
passphrase alone decrypts. Only a SHA-256 hash of it is ever sent.

```ts
await lp.secrets.create({ secret: "…", passphrase: "correct horse" });
```

The passphrase is normalized to Unicode NFKC before it is stretched and
before it is hashed. The same visible passphrase can be different bytes on
two devices: a precomposed `é` or an `e` plus a combining accent, or
full-width characters from a Japanese input method. Without normalization the
recipient types the right passphrase and cannot decrypt. It is never trimmed
and never case-folded, and an ASCII passphrase produces the same bytes as
before.

To open a secret yourself, pass the passphrase as it was typed to
`crypto.decryptPayload` or `crypto.resolveContentKey`. They try the NFKC
form, the string as typed, NFC and NFD, and use the one whose key
authenticates the ciphertext, so secrets written before this rule still open.
If you call the API without the SDK, send `passphrase_hash` as the SHA-256
hex of the NFKC form.

## Short links

```ts
const link = await lp.links.create({ url: "https://example.com/launch", tags: ["campaign"] });
const page = await lp.links.list({ limit: 20 });
await lp.links.delete(link.id);
```

## Errors

Branch on a code rather than matching message text:

```ts
import { LinkPilotApiError } from "@uselinkpilot/sdk";

try {
  await lp.links.create({ url });
} catch (e) {
  if (e instanceof LinkPilotApiError) {
    if (e.needsUpgrade) console.error(`Plan limit. ${e.upgradeUrl}`);
    else if (e.isRetryable) console.error(`Retry in ${e.retryAfterSeconds ?? 5}s`);
    else if (e.isDisabled) console.error("The API is not enabled for this deployment yet.");
  }
}
```

## Requirements

Node 20+, Deno, Bun, or any runtime with WebCrypto. No dependencies.

## Verifying the encryption

`test/crypto.vectors.test.ts` runs the same committed known-answer vectors the
LinkPilot web app uses. If this package and the web app ever disagree about
the wire format, those tests fail. `test/passphraseNormalization.test.ts`
does the same for passphrase normalization, including secrets written before
the rule existed. The format is specified in `docs/secret-encryption.md` in
the LinkPilot repository.
