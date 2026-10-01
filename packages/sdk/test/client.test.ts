/**
 * Client tests against a fake transport.
 *
 * The assertion that matters most is negative: for every secret path, the
 * plaintext and the key must NOT appear anywhere in the request. Everything
 * else here is shape-checking; that one is the product guarantee.
 */

import { describe, it, expect } from "vitest";
import { LinkPilot, LinkPilotApiError, API_KEY_PREFIX } from "../src/index.js";
import { decryptPayload, readFragmentKey } from "../src/crypto.js";

const KEY = `${API_KEY_PREFIX}0123456789abcdef0123456789abcdef`;

interface Captured {
  url: string;
  method: string;
  headers: Record<string, string>;
  body?: unknown;
  rawBody?: string;
}

/** A fetch stand-in that records the request and replays a scripted response. */
function fakeFetch(
  script: (req: Captured) => { status?: number; body?: unknown; headers?: Record<string, string> },
) {
  const calls: Captured[] = [];
  const fn = (async (input: string | URL, init?: RequestInit) => {
    const raw = typeof init?.body === "string" ? init.body : undefined;
    const captured: Captured = {
      url: String(input),
      method: init?.method ?? "GET",
      headers: (init?.headers ?? {}) as Record<string, string>,
      rawBody: raw,
      body: raw ? JSON.parse(raw) : undefined,
    };
    calls.push(captured);
    const out = script(captured);
    const status = out.status ?? 200;
    return new Response(status === 204 ? null : JSON.stringify(out.body ?? {}), {
      status,
      headers: { "Content-Type": "application/json", ...(out.headers ?? {}) },
    });
  }) as unknown as typeof globalThis.fetch;
  return { fn, calls };
}

describe("construction", () => {
  it("rejects a key that is not an lp_live_ key, immediately", () => {
    // Better than a confusing 401 three calls later.
    expect(() => new LinkPilot({ apiKey: "sk_test_nope" })).toThrow(/lp_live_/);
  });

  it("refuses an authenticated call with no key", async () => {
    const c = new LinkPilot();
    await expect(c.me()).rejects.toThrow(/needs an API key/);
  });

  it("sends the key as a bearer token and never in the URL", async () => {
    const f = fakeFetch(() => ({ body: { plan: "free", limits: {}, usage: {} } }));
    await new LinkPilot({ apiKey: KEY, fetch: f.fn }).me();
    expect(f.calls[0].headers.Authorization).toBe(`Bearer ${KEY}`);
    expect(f.calls[0].url).not.toContain(KEY);
  });
});

describe("secrets.create: the plaintext must never leave the process", () => {
  const SECRET = "db password: hunter2-UNIQUE-MARKER";

  it("sends ciphertext and enc_version, never the payload", async () => {
    const f = fakeFetch(() => ({
      status: 201,
      body: {
        id: "sec_1",
        secret_url: "https://shrd.link/s/abcdefghij",
        expires_at: null,
        burn_after_read: true,
      },
    }));
    const c = new LinkPilot({ apiKey: KEY, fetch: f.fn });
    const out = await c.secrets.create({ secret: SECRET });

    const req = f.calls[0];
    const body = req.body as Record<string, unknown>;

    // The guarantee, asserted three ways.
    expect(req.rawBody).not.toContain(SECRET);
    expect(req.rawBody).not.toContain(out.fragmentKey);
    expect(body.payload).toBeUndefined();

    expect(String(body.ciphertext).startsWith("v1.")).toBe(true);
    expect(body.enc_version).toBe(1);
  });

  it("returns a share URL that actually opens, and a bare URL that does not", async () => {
    const f = fakeFetch(() => ({
      status: 201,
      body: {
        id: "sec_1",
        secret_url: "https://shrd.link/s/abcdefghij",
        expires_at: null,
        burn_after_read: true,
      },
    }));
    const c = new LinkPilot({ apiKey: KEY, fetch: f.fn });
    const out = await c.secrets.create({ secret: SECRET });

    expect(out.secretUrl).toBe("https://shrd.link/s/abcdefghij");
    expect(out.secretUrl).not.toContain("#");
    expect(out.shareUrl).toBe(`https://shrd.link/s/abcdefghij#k=${out.fragmentKey}`);

    // End to end: the key off the share URL decrypts what was sent.
    const sent = (f.calls[0].body as { ciphertext: string }).ciphertext;
    const key = readFragmentKey(out.shareUrl.slice(out.shareUrl.indexOf("#")));
    expect(await decryptPayload(sent, key)).toBe(SECRET);
  });

  it("sends a passphrase only as a SHA-256 hash, and uses the v1p shape", async () => {
    const f = fakeFetch(() => ({
      status: 201,
      body: { id: "s", secret_url: "https://shrd.link/s/aaaaaaaaaa", expires_at: null, burn_after_read: true },
    }));
    const c = new LinkPilot({ apiKey: KEY, fetch: f.fn });
    const out = await c.secrets.create({ secret: SECRET, passphrase: "open sesame" });

    const body = f.calls[0].body as Record<string, string>;
    expect(f.calls[0].rawBody).not.toContain("open sesame");
    expect(body.passphrase).toBeUndefined();
    expect(body.passphrase_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(body.ciphertext.startsWith("v1p.")).toBe(true);

    // Needs BOTH halves.
    const key = out.fragmentKey;
    await expect(decryptPayload(body.ciphertext, key)).rejects.toThrow();
    expect(await decryptPayload(body.ciphertext, key, "open sesame")).toBe(SECRET);
  });

  it("omits optional fields rather than sending undefined", async () => {
    const f = fakeFetch(() => ({
      status: 201,
      body: { id: "s", secret_url: "https://shrd.link/s/aaaaaaaaaa", expires_at: null, burn_after_read: true },
    }));
    await new LinkPilot({ apiKey: KEY, fetch: f.fn }).secrets.create({ secret: "x" });
    const body = f.calls[0].body as Record<string, unknown>;
    expect(Object.keys(body).sort()).toEqual(["ciphertext", "enc_version"]);
  });
});

describe("anonymous secrets", () => {
  it("encrypts too, and never sends a passphrase hash", async () => {
    const f = fakeFetch(() => ({
      status: 201,
      body: { id: "s", secret_url: "https://shrd.link/s/bbbbbbb", expires_at: null, burn_after_read: true },
    }));
    const c = new LinkPilot({ fetch: f.fn });
    const out = await c.anonymous.createSecret({
      secret: "anon secret",
      clientId: "cli-0123456789abcdef",
      turnstileToken: "tok",
    });
    const body = f.calls[0].body as Record<string, unknown>;
    expect(f.calls[0].rawBody).not.toContain("anon secret");
    expect(body.enc_version).toBe(1);
    expect(String(body.ciphertext).startsWith("v1.")).toBe(true);
    expect(body.passphrase_hash).toBeUndefined();
    expect(f.calls[0].headers.Authorization).toBeUndefined();
    expect(out.shareUrl).toContain("#k=");
  });
});

describe("links", () => {
  it("creates, lists, gets and deletes against the right routes", async () => {
    const f = fakeFetch((req) =>
      req.method === "DELETE" ? { status: 204 } : { body: { data: [], next_cursor: null } },
    );
    const c = new LinkPilot({ apiKey: KEY, fetch: f.fn });
    await c.links.create({ url: "https://example.com" });
    await c.links.list({ limit: 10 });
    await c.links.get("abc");
    await c.links.delete("abc");

    expect(f.calls.map((x) => `${x.method} ${new URL(x.url).pathname.split("/api-v1")[1]}`)).toEqual([
      "POST /links",
      "GET /links",
      "GET /links/abc",
      "DELETE /links/abc",
    ]);
    expect(f.calls[1].url).toContain("limit=10");
  });

  it("URL-encodes an id rather than letting it alter the path", async () => {
    const f = fakeFetch(() => ({ status: 204 }));
    await new LinkPilot({ apiKey: KEY, fetch: f.fn }).links.delete("../secrets/evil");
    expect(f.calls[0].url).toContain("%2E%2E%2Fsecrets%2Fevil".replace(/%2E/g, "."));
    expect(new URL(f.calls[0].url).pathname).not.toContain("/secrets/");
  });
});

describe("errors", () => {
  it("maps the API's error envelope to a typed error", async () => {
    const f = fakeFetch(() => ({
      status: 402,
      body: { error: { code: "plan_limit", message: "Too many links.", upgrade_url: "https://x/pricing" } },
    }));
    const c = new LinkPilot({ apiKey: KEY, fetch: f.fn });
    const err = await c.links.create({ url: "https://example.com" }).catch((e) => e);
    expect(err).toBeInstanceOf(LinkPilotApiError);
    expect(err.code).toBe("plan_limit");
    expect(err.status).toBe(402);
    expect(err.needsUpgrade).toBe(true);
    expect(err.isRetryable).toBe(false);
    expect(err.upgradeUrl).toBe("https://x/pricing");
  });

  it("surfaces a dark API distinctly from a server fault", async () => {
    // Retrying a 503 disabled will never help; retrying a 500 might.
    const f = fakeFetch(() => ({ status: 503, body: { error: { code: "disabled", message: "off" } } }));
    const err = await new LinkPilot({ apiKey: KEY, fetch: f.fn }).me().catch((e) => e);
    expect(err.isDisabled).toBe(true);
    expect(err.needsUpgrade).toBe(false);
  });

  it("reads Retry-After on a rate limit", async () => {
    const f = fakeFetch(() => ({
      status: 429,
      body: { error: { code: "rate_limited", message: "slow down" } },
      headers: { "Retry-After": "42" },
    }));
    const err = await new LinkPilot({ apiKey: KEY, fetch: f.fn }).me().catch((e) => e);
    expect(err.retryAfterSeconds).toBe(42);
    expect(err.isRetryable).toBe(true);
  });

  it("does not choke on a non-JSON error page", async () => {
    // A gateway returning HTML must not produce a JSON parse crash, and must
    // not paste the page into the exception message.
    const fn = (async () =>
      new Response("<html>502 Bad Gateway</html>", {
        status: 502,
        headers: { "Content-Type": "text/html" },
      })) as unknown as typeof globalThis.fetch;
    const err = await new LinkPilot({ apiKey: KEY, fetch: fn }).me().catch((e) => e);
    expect(err).toBeInstanceOf(LinkPilotApiError);
    expect(err.code).toBe("unknown_error");
    expect(err.status).toBe(502);
    expect(err.message).not.toContain("<html>");
    expect(err.isRetryable).toBe(true);
  });
});

describe("default fetch binding", () => {
  it("works on a runtime that rejects a detached global fetch, as Cloudflare Workers do", async () => {
    // workerd throws TypeError("Illegal invocation") when a global function is
    // called with any `this` other than undefined/globalThis. Node does not,
    // which is how a client that stored globalThis.fetch and called it as a
    // method passed every test here and failed on every Worker.
    const realFetch = globalThis.fetch;
    const strictFetch = function (this: unknown, input: RequestInfo | URL, init?: RequestInit) {
      if (this !== undefined && this !== globalThis) {
        throw new TypeError("Illegal invocation: function called with incorrect `this` reference");
      }
      return Promise.resolve(
        new Response(JSON.stringify({ tenant: { id: "t", name: "T" }, plan: { slug: "free", name: "Free" }, limits: {}, usage: {}, rate_limit: {} }), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
      );
    };
    globalThis.fetch = strictFetch as unknown as typeof fetch;
    try {
      const client = new LinkPilot({ apiKey: "lp_live_test_key_0000000000" });
      const me = await client.me();
      expect(me.tenant.name).toBe("T");
    } finally {
      globalThis.fetch = realFetch;
    }
  });
});
