# linkpilot

Create [LinkPilot](https://uselinkpilot.com) short links and end-to-end
encrypted secret links from your terminal.

```bash
npm install -g linkpilot
linkpilot login
```

## Secrets

```bash
echo 'db password: hunter2' | linkpilot secret
linkpilot secret < credentials.txt
linkpilot secret            # prompts, input hidden
```

**Pipe the secret in.** Passing it as an argument works, and warns, because
it puts the secret in your shell history and in the process list where other
users can see it with `ps`:

```bash
linkpilot secret 'hunter2'
# warning: The secret was passed as a command-line argument, so it is now in
# your shell history and was visible in the process list. …
```

The output is a link with the decryption key in the `#` fragment:

```
https://shrd.link/s/abcdefghij#k=…
```

That key is generated on your machine and never sent. LinkPilot stores
ciphertext, cannot read the secret, and cannot recover it. **If you lose the
printed link, the secret is gone.**

Options: `--ttl 2h` (also `30m`, `7d`, or plain seconds), `--passphrase`,
`--no-burn` to allow more than one view, `--quiet` to print only the URL.

```bash
URL=$(echo "$TOKEN" | linkpilot secret --ttl 30m --quiet)
```

## Short links

```bash
linkpilot shorten https://example.com/launch --slug launch --tags campaign,q4
linkpilot links
```

## Authentication

In order of priority:

1. `--key lp_live_…`
2. `LINKPILOT_API_KEY` — use this in CI
3. the file written by `linkpilot login`

The file lives in your OS config directory and is written `0600`, readable
only by you. `linkpilot whoami` shows a masked key and your plan; the full
key is never printed. `linkpilot logout` removes it.

Create a key at <https://uselinkpilot.com/app/api-keys>.

## Commands

| | |
|---|---|
| `secret [text]` | Create a secret link |
| `shorten <url>` | Create a short link |
| `links` / `secrets` | List them (secrets are metadata only) |
| `revoke <id>` | Revoke a secret link |
| `login` / `logout` / `whoami` | Manage the stored key |

`--json` on any command for machine-readable output.

Requires Node 20+.
