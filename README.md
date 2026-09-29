# LinkPilot SDK and CLI

Official TypeScript client and command-line tool for [LinkPilot](https://uselinkpilot.com):
branded short links, and one-time secret links that are **encrypted in your
process before they are sent**.

| package | install | what it is |
|---|---|---|
| [`@uselinkpilot/sdk`](packages/sdk) | `npm i @uselinkpilot/sdk` | Typed client for the LinkPilot API v1 |
| [`linkpilot`](packages/cli) | `npm i -g linkpilot` | Command-line tool built on the SDK |

API reference: <https://uselinkpilot.com/developers>

## Why a client library is required for secrets

LinkPilot's API **will not accept a plaintext secret**. `POST /secrets` takes
ciphertext and an `enc_version`, and rejects a `payload` field outright.

That is not an awkward API design to work around. It is the product
guarantee: the decryption key is generated on your machine, travels in the
`#` fragment of the share link, and is never transmitted. LinkPilot stores a
blob it holds no key for and cannot read. Neither can anyone who reaches its
database or its edge.

So any client that creates a secret has to do the encryption itself. This SDK
does it once, correctly, so that every downstream tool does not have to.

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

**Send `shareUrl`, never `secretUrl`.** The part after the `#` is the key.
A URL without it opens nothing, for anyone, including us. There is no
recovery path: lose the share URL and the secret is gone. That is the
guarantee working, not a gap.

From the terminal, the same thing:

```bash
echo 'db password: hunter2' | linkpilot secret --ttl 1h
```

Pipe the secret in rather than passing it as an argument. An argument lands
in your shell history and is visible in the process list. The CLI warns you
when it happens.

## Verifying the encryption

You do not have to take the above on trust.

The wire format is specified publicly at
<https://uselinkpilot.com/developers>, and this package's test suite runs the
**same committed known-answer vectors** that the LinkPilot web application
uses. If this implementation and the one serving the reveal page ever
disagreed about a single byte, those tests would fail:

```bash
npm test
```

There are three independent implementations of the format — the web
application, the reveal page served at the edge, and this package — and the
vectors are what keep them honest.

## Development

```bash
npm ci
npm run build      # the CLI's types come from the SDK's build output, so this first
npm run typecheck
npm test
```

This is an npm workspace. `packages/sdk` has no dependencies and uses only
WebCrypto, so it runs unchanged on Node 20+, Deno, Bun, browsers and edge
runtimes. `packages/cli` depends on the SDK and nothing else.

Continuous integration runs on Linux, macOS and Windows across Node 20 and
22, because the CLI stores an API key in a file whose location and
permissions differ per platform.

## Releases

Published from CI with [npm provenance](https://docs.npmjs.com/generating-provenance-statements),
so each release carries a signed attestation tying the published tarball to a
specific commit in this repository.

## Licence

MIT
