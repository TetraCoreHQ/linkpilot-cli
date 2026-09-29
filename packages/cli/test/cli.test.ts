/**
 * CLI tests.
 *
 * Weighted towards the ways a credential tool leaks: an API key printed in
 * full, a secret taken from argv without warning, a key file left
 * world-readable, a secret echoed back to the terminal.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, statSync, readFileSync, existsSync } from "node:fs";
import { tmpdir, platform } from "node:os";
import { join } from "node:path";
import { Readable } from "node:stream";

import { run } from "../src/run.js";
import { parseArgs, parseTtl } from "../src/args.js";
import { maskKey, configPath, writeStored, readStored, resolveKey } from "../src/credentials.js";
import { resolveSecret } from "../src/input.js";
import { VERSION } from "../src/run.js";

const KEY = "lp_live_0123456789abcdef0123456789abcdef";

let dir: string;
let env: NodeJS.ProcessEnv;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "lp-cli-"));
  env = { LINKPILOT_CONFIG_DIR: dir };
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

function harness(extra: Partial<Parameters<typeof run>[1]> = {}) {
  const out: string[] = [];
  const err: string[] = [];
  const calls: Array<{ method: string; args: unknown }> = [];
  const fakeClient = {
    me: async () => {
      calls.push({ method: "me", args: null });
      // The REAL shape, copied from a live GET /me. The previous fake here
      // invented `plan: "pro"` as a string, which let a wrong SDK type pass
      // review and made the CLI print "[object Object]" against production.
      return {
        tenant: { id: "t1", name: "Acme Inc" },
        plan: { slug: "pro", name: "Pro" },
        limits: {
          max_links: null,
          max_domains: 5,
          max_active_secrets: 100,
          secret_passphrase_enabled: true,
          analytics_history_days: null,
        },
        usage: { links: 3, secrets: 1, domains: 0 },
        rate_limit: { limit_per_hour: 1000, remaining: 994, reset_at: "2026-09-29T15:06:08.000Z" },
      };
    },
    secrets: {
      create: async (a: unknown) => {
        calls.push({ method: "secrets.create", args: a });
        return {
          id: "sec_1",
          secretUrl: "https://shrd.link/s/abcdefghij",
          shareUrl: "https://shrd.link/s/abcdefghij#k=KEYKEYKEY",
          fragmentKey: "KEYKEYKEY",
          expiresAt: null,
          burnAfterRead: true,
        };
      },
      list: async () => ({ data: [], next_cursor: null }),
      revoke: async (id: string) => {
        calls.push({ method: "secrets.revoke", args: id });
      },
    },
    links: {
      create: async (a: unknown) => {
        calls.push({ method: "links.create", args: a });
        return {
          id: "l1",
          short_url: "https://shrd.link/abc",
          url: "https://example.com",
          slug: "abc",
          title: null,
          tags: [],
          total_clicks: 0,
          expires_at: null,
          created_at: "",
        };
      },
      list: async () => ({ data: [], next_cursor: null }),
    },
  };
  return {
    out,
    err,
    calls,
    deps: {
      env,
      out: (s: string) => out.push(s),
      err: (s: string) => err.push(s),
      makeClient: () => fakeClient as never,
      interactive: false,
      ...extra,
    },
  };
}

/** stdin that looks piped and yields the given text. */
function pipedStdin(text: string): NodeJS.ReadStream {
  const s = Readable.from([Buffer.from(text, "utf8")]) as unknown as NodeJS.ReadStream;
  (s as unknown as { isTTY: boolean }).isTTY = false;
  return s;
}

/** stdin that looks like a terminal and yields nothing. */
function ttyStdin(): NodeJS.ReadStream {
  const s = Readable.from([]) as unknown as NodeJS.ReadStream;
  (s as unknown as { isTTY: boolean }).isTTY = true;
  return s;
}

describe("argument parsing", () => {
  it("separates the command, positionals and flags", () => {
    const p = parseArgs(["secret", "hello world", "--ttl", "2h", "--json"]);
    expect(p.command).toBe("secret");
    expect(p.positional).toEqual(["hello world"]);
    expect(p.flags).toEqual({ ttl: "2h", json: true });
  });

  it("lets -- protect a secret that begins with a dash", () => {
    const p = parseArgs(["secret", "--", "--not-a-flag"]);
    expect(p.positional).toEqual(["--not-a-flag"]);
    expect(p.flags["not-a-flag"]).toBeUndefined();
  });

  it("accepts --flag=value", () => {
    expect(parseArgs(["shorten", "--slug=launch"]).flags.slug).toBe("launch");
  });

  it("parses human durations", () => {
    expect(parseTtl("3600")).toBe(3600);
    expect(parseTtl("30m")).toBe(1800);
    expect(parseTtl("2h")).toBe(7200);
    expect(parseTtl("7d")).toBe(604800);
    expect(() => parseTtl("soon")).toThrow(/3600, 30m, 2h or 7d/);
  });
});

describe("the API key is never printed in full", () => {
  it("masks it everywhere it is shown", () => {
    const masked = maskKey(KEY);
    expect(masked).not.toBe(KEY);
    expect(masked).not.toContain("0123456789abcdef0123456789abcdef");
    expect(masked.startsWith("lp_live_")).toBe(true);
    expect(masked).toContain("…");
  });

  it("whoami shows only the mask", async () => {
    writeStored({ apiKey: KEY }, env);
    const h = harness();
    expect(await run(["whoami"], h.deps)).toBe(0);
    const printed = h.out.join("\n");
    expect(printed).toContain("lp_live_");
    expect(printed).not.toContain(KEY);
    // Renders the nested plan rather than "[object Object]".
    expect(printed).toContain("Pro");
    expect(printed).toContain("Acme Inc");
    expect(printed).not.toContain("[object Object]");
    // A null cap reads as "unlimited", not "null".
    expect(printed).toMatch(/links\s+3 of unlimited/);
  });

  it("does not leak the key even in --json", async () => {
    writeStored({ apiKey: KEY }, env);
    const h = harness();
    await run(["whoami", "--json"], h.deps);
    expect(h.out.join("\n")).not.toContain(KEY);
  });
});

describe("credential storage", () => {
  it("writes the file readable only by the owner", () => {
    const p = writeStored({ apiKey: KEY }, env);
    expect(readStored(env)?.apiKey).toBe(KEY);
    if (platform() !== "win32") {
      // 0600. Anything wider and another local user can read the key.
      expect(statSync(p).mode & 0o777).toBe(0o600);
    }
  });

  it("treats a corrupt file as no file rather than crashing", () => {
    writeStored({ apiKey: KEY }, env);
    require("node:fs").writeFileSync(configPath(env), "{ not json");
    expect(readStored(env)).toBeNull();
  });

  it("ignores a stored value that is not a LinkPilot key", () => {
    require("node:fs").writeFileSync(configPath(env), JSON.stringify({ apiKey: "hunter2" }));
    expect(readStored(env)).toBeNull();
  });

  it("prefers the environment variable over the stored key", () => {
    writeStored({ apiKey: KEY }, env);
    const withEnv = { ...env, LINKPILOT_API_KEY: "lp_live_fromenv" };
    expect(resolveKey(undefined, withEnv)).toMatchObject({ apiKey: "lp_live_fromenv", source: "env" });
    // …and an explicit flag beats both.
    expect(resolveKey("lp_live_flag", withEnv)).toMatchObject({ source: "flag" });
  });

  it("logout removes the file and warns if the env var still shadows it", async () => {
    writeStored({ apiKey: KEY }, env);
    const h = harness({ env: { ...env, LINKPILOT_API_KEY: KEY } });
    await run(["logout"], h.deps);
    expect(existsSync(configPath(env))).toBe(false);
    expect(h.err.join("\n")).toMatch(/still set/);
  });
});

describe("how the secret gets in", () => {
  it("reads stdin when piped and strips one trailing newline", async () => {
    // `echo hunter2 |` is the obvious thing to type.
    const r = await resolveSecret({ stdin: pipedStdin("hunter2\n") });
    expect(r).toEqual({ value: "hunter2", source: "stdin" });
  });

  it("keeps internal newlines and leading spaces, which can be meaningful", async () => {
    const pem = "-----BEGIN KEY-----\nabc\ndef\n-----END KEY-----\n";
    const r = await resolveSecret({ stdin: pipedStdin(pem) });
    expect(r.value).toBe(pem.replace(/\n$/, ""));
  });

  it("WARNS when the secret came from argv", async () => {
    // argv lands in shell history and in `ps`. Still allowed, never silent.
    const r = await resolveSecret({ argument: "hunter2", stdin: ttyStdin(), interactive: false });
    expect(r.source).toBe("argument");
    expect(r.warning).toMatch(/shell history/);
    expect(r.warning).toMatch(/process list/);
  });

  it("surfaces that warning to stderr, not stdout", async () => {
    const h = harness({ stdin: ttyStdin() });
    writeStored({ apiKey: KEY }, env);
    await run(["secret", "hunter2"], h.deps);
    expect(h.err.join("\n")).toMatch(/shell history/);
    // stdout stays clean so `$(linkpilot secret … --quiet)` is usable.
    expect(h.out.join("\n")).not.toMatch(/shell history/);
  });

  it("refuses an empty pipe rather than creating an empty secret", async () => {
    await expect(resolveSecret({ stdin: pipedStdin("") })).rejects.toThrow(/Nothing on stdin/);
  });

  it("falls back to the argument when stdin is not a TTY but is empty", async () => {
    // The shape that broke when the real binary was first run in a
    // non-interactive shell: a script or CI run has stdin on /dev/null, which
    // is "piped" but carries nothing. Erroring there made the documented
    // argument form unusable outside an interactive terminal.
    const r = await resolveSecret({ argument: "hunter2", stdin: pipedStdin(""), interactive: false });
    expect(r.value).toBe("hunter2");
    expect(r.source).toBe("argument");
    expect(r.warning).toMatch(/shell history/);
  });

  it("still prefers real piped input over an argument", async () => {
    const r = await resolveSecret({ argument: "from-argv", stdin: pipedStdin("from-stdin\n") });
    expect(r.value).toBe("from-stdin");
    expect(r.source).toBe("stdin");
  });
});

describe("secret command", () => {
  beforeEach(() => writeStored({ apiKey: KEY }, env));

  it("prints the share URL, which is the one with the key", async () => {
    const h = harness({ stdin: pipedStdin("hunter2\n") });
    expect(await run(["secret"], h.deps)).toBe(0);
    const printed = h.out.join("\n");
    expect(printed).toContain("#k=KEYKEYKEY");
    expect(printed).toMatch(/cannot recover/);
  });

  it("--quiet prints the URL and nothing else, for scripting", async () => {
    const h = harness({ stdin: pipedStdin("hunter2\n") });
    await run(["secret", "--quiet"], h.deps);
    expect(h.out).toEqual(["https://shrd.link/s/abcdefghij#k=KEYKEYKEY"]);
  });

  it("never echoes the secret back to the user", async () => {
    const h = harness({ stdin: pipedStdin("SUPER-SECRET-MARKER\n") });
    await run(["secret"], h.deps);
    expect(h.out.join("\n")).not.toContain("SUPER-SECRET-MARKER");
    expect(h.err.join("\n")).not.toContain("SUPER-SECRET-MARKER");
  });

  it("passes ttl, passphrase and --no-burn through", async () => {
    const h = harness({ stdin: pipedStdin("x\n") });
    await run(["secret", "--ttl", "2h", "--passphrase", "open sesame", "--no-burn"], h.deps);
    expect(h.calls[0].args).toMatchObject({
      secret: "x",
      ttlSeconds: 7200,
      passphrase: "open sesame",
      burnAfterRead: false,
    });
  });
});

describe("dispatch", () => {
  it("exits non-zero with help when given no command", async () => {
    const h = harness();
    expect(await run([], h.deps)).toBe(1);
    expect(h.out.join("\n")).toContain("USAGE");
  });

  it("exits zero for explicit --help", async () => {
    const h = harness();
    expect(await run(["--help"], h.deps)).toBe(0);
  });

  it("rejects an unknown command without a stack trace", async () => {
    const h = harness();
    expect(await run(["frobnicate"], h.deps)).toBe(1);
    expect(h.err.join("\n")).toContain('Unknown command "frobnicate"');
  });

  it("tells the user how to authenticate when there is no key", async () => {
    const h = harness({ env: { LINKPILOT_CONFIG_DIR: dir } });
    expect(await run(["links"], h.deps)).toBe(1);
    expect(h.err.join("\n")).toMatch(/linkpilot login/);
    expect(h.err.join("\n")).toMatch(/api-keys/);
  });

  it("explains a dark API rather than showing a raw 503", async () => {
    writeStored({ apiKey: KEY }, env);
    const { LinkPilotApiError } = await import("@uselinkpilot/sdk");
    const h = harness();
    h.deps.makeClient = () =>
      ({
        links: {
          list: async () => {
            throw new LinkPilotApiError({ code: "disabled", status: 503, message: "off" });
          },
        },
      }) as never;
    expect(await run(["links"], h.deps)).toBe(1);
    expect(h.err.join("\n")).toMatch(/not switched on/);
  });
});

describe("the reported version", () => {
  it("matches package.json", () => {
    // 0.1.1 shipped announcing itself as 0.1.0, because the constant was
    // hand-maintained and the release bumped only the manifest.
    const pkg = JSON.parse(
      readFileSync(new URL("../package.json", import.meta.url), "utf8"),
    ) as { version: string };
    expect(VERSION).toBe(pkg.version);
  });
});
