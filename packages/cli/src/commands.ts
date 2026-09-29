/**
 * The commands themselves, kept free of process globals so they can be
 * tested without spawning anything.
 */

import { LinkPilot, LinkPilotApiError } from "@uselinkpilot/sdk";
import {
  API_KEY_PREFIX,
  clearStored,
  configPath,
  ENV_VAR,
  maskKey,
  resolveKey,
  writeStored,
} from "./credentials.js";
import { flagNumber, flagString, parseTtl, type ParsedArgs } from "./args.js";
import { resolveSecret } from "./input.js";

export interface Ctx {
  argv: ParsedArgs;
  env: NodeJS.ProcessEnv;
  out: (s: string) => void;
  err: (s: string) => void;
  /** Injected in tests. */
  makeClient?: (opts: { apiKey?: string; baseUrl?: string }) => LinkPilot;
  stdin?: NodeJS.ReadStream;
  interactive?: boolean;
}

export const HELP = `linkpilot — short links and end-to-end encrypted secrets

USAGE
  linkpilot <command> [options]

COMMANDS
  secret [text]        Create a secret link. Prefer stdin (see below).
  shorten <url>        Create a short link.
  links                List your short links.
  secrets              List your secret links (metadata only).
  revoke <id>          Revoke a secret link.
  login                Store an API key for this machine.
  logout               Remove the stored API key.
  whoami               Show the plan, limits and usage for the current key.

SECRETS ARE ENCRYPTED HERE, NOT ON THE SERVER
  The key is generated in this process, put in the "#" part of the link, and
  never sent. LinkPilot cannot read your secret and cannot recover it. If you
  lose the printed link, it is gone.

  Pass the secret on STDIN where you can. An argument ends up in your shell
  history and in the process list:
      echo 'hunter2' | linkpilot secret
      linkpilot secret < secret.txt
      linkpilot secret                 # prompts, input hidden

OPTIONS
  --ttl <dur>          Lifetime: 3600, 30m, 2h, 7d. Default: server default.
  --passphrase <s>     Second factor. Folded into the key; only a hash is sent.
  --no-burn            Allow more than one view (secrets are burn-after-read).
  --json               Machine-readable output.
  --quiet              Print only the resulting URL.
  --key <lp_live_…>    Use this key instead of the stored one.
  --help, --version

AUTHENTICATION
  ${ENV_VAR} wins over the stored key, which is what CI should use.
`;

function client(ctx: Ctx, opts: { requireKey: boolean }): LinkPilot {
  const resolved = resolveKey(flagString(ctx.argv.flags, "key"), ctx.env);
  if (opts.requireKey && !resolved) {
    throw new Error(
      `No API key. Run "linkpilot login", or set ${ENV_VAR}. Create a key at https://uselinkpilot.com/app/api-keys`,
    );
  }
  const baseUrl = flagString(ctx.argv.flags, "base-url") ?? resolved?.baseUrl;
  const make = ctx.makeClient ?? ((o) => new LinkPilot(o));
  return make({ apiKey: resolved?.apiKey, baseUrl });
}

function emit(ctx: Ctx, human: string, data: unknown): void {
  if (ctx.argv.flags.json) ctx.out(JSON.stringify(data, null, 2));
  else ctx.out(human);
}

export async function cmdSecret(ctx: Ctx): Promise<number> {
  const lp = client(ctx, { requireKey: true });

  const input = await resolveSecret({
    argument: ctx.argv.positional.join(" ") || undefined,
    stdin: ctx.stdin,
    interactive: ctx.interactive,
  });
  if (input.warning) ctx.err(`warning: ${input.warning}`);

  const created = await lp.secrets.create({
    secret: input.value,
    passphrase: flagString(ctx.argv.flags, "passphrase"),
    ttlSeconds: parseTtl(flagString(ctx.argv.flags, "ttl")) ?? flagNumber(ctx.argv.flags, "ttl-seconds"),
    burnAfterRead: ctx.argv.flags["no-burn"] ? false : undefined,
  });

  if (ctx.argv.flags.quiet) {
    ctx.out(created.shareUrl);
    return 0;
  }

  emit(
    ctx,
    [
      created.shareUrl,
      "",
      "This link contains the decryption key. It is the only copy: LinkPilot",
      "cannot read the secret and cannot recover it if the link is lost.",
      created.burnAfterRead ? "It self-destructs after one view." : "",
    ]
      .filter(Boolean)
      .join("\n"),
    {
      id: created.id,
      share_url: created.shareUrl,
      secret_url: created.secretUrl,
      expires_at: created.expiresAt,
      burn_after_read: created.burnAfterRead,
    },
  );
  return 0;
}

export async function cmdShorten(ctx: Ctx): Promise<number> {
  const url = ctx.argv.positional[0];
  if (!url) throw new Error("Usage: linkpilot shorten <url>");
  const lp = client(ctx, { requireKey: true });

  const link = await lp.links.create({
    url,
    slug: flagString(ctx.argv.flags, "slug"),
    domain: flagString(ctx.argv.flags, "domain"),
    title: flagString(ctx.argv.flags, "title"),
    tags: flagString(ctx.argv.flags, "tags")?.split(",").map((t) => t.trim()).filter(Boolean),
  });

  if (ctx.argv.flags.quiet) ctx.out(link.short_url);
  else emit(ctx, link.short_url, link);
  return 0;
}

export async function cmdLinks(ctx: Ctx): Promise<number> {
  const lp = client(ctx, { requireKey: true });
  const page = await lp.links.list({ limit: flagNumber(ctx.argv.flags, "limit") ?? 20 });
  emit(
    ctx,
    page.data.length === 0
      ? "No links yet."
      : page.data.map((l) => `${l.short_url}  ${l.total_clicks} clicks  ${l.url}`).join("\n"),
    page,
  );
  return 0;
}

export async function cmdSecrets(ctx: Ctx): Promise<number> {
  const lp = client(ctx, { requireKey: true });
  const page = await lp.secrets.list({ limit: flagNumber(ctx.argv.flags, "limit") ?? 20 });
  emit(
    ctx,
    page.data.length === 0
      ? "No secret links yet."
      : [
          "Metadata only — no route returns a payload, and the key was never sent.",
          ...page.data.map((s) => `${s.id}  ${s.status.padEnd(8)}  ${s.view_count} views  ${s.secret_url}`),
        ].join("\n"),
    page,
  );
  return 0;
}

export async function cmdRevoke(ctx: Ctx): Promise<number> {
  const id = ctx.argv.positional[0];
  if (!id) throw new Error("Usage: linkpilot revoke <secret id>");
  await client(ctx, { requireKey: true }).secrets.revoke(id);
  emit(ctx, `Revoked ${id}.`, { id, revoked: true });
  return 0;
}

export async function cmdWhoami(ctx: Ctx): Promise<number> {
  const resolved = resolveKey(flagString(ctx.argv.flags, "key"), ctx.env);
  if (!resolved) {
    ctx.err(`Not logged in. Run "linkpilot login" or set ${ENV_VAR}.`);
    return 1;
  }
  const me = await client(ctx, { requireKey: true }).me();
  const cap = (n: number | null) => (n === null ? "unlimited" : String(n));
  emit(
    ctx,
    [
      `key        ${maskKey(resolved.apiKey)}  (from ${resolved.source})`,
      `workspace  ${me.tenant.name}`,
      `plan       ${me.plan.name}`,
      `links      ${me.usage.links} of ${cap(me.limits.max_links)}`,
      `secrets    ${me.usage.secrets} of ${cap(me.limits.max_active_secrets)} active`,
      `domains    ${me.usage.domains} of ${cap(me.limits.max_domains)}`,
      `requests   ${me.rate_limit.remaining} of ${me.rate_limit.limit_per_hour} left this hour`,
    ].join("\n"),
    { key: maskKey(resolved.apiKey), source: resolved.source, ...me },
  );
  return 0;
}

export async function cmdLogin(ctx: Ctx): Promise<number> {
  // Accept --key, else prompt. Never accept it as a positional argument:
  // that would put the key in shell history for no good reason.
  let key = flagString(ctx.argv.flags, "key");
  if (!key) {
    const { promptHidden } = await import("./input.js");
    key = (await promptHidden("API key (input hidden): ")).trim();
  }
  if (!key.startsWith(API_KEY_PREFIX)) {
    throw new Error(`That does not look like a LinkPilot key. Keys start with "${API_KEY_PREFIX}".`);
  }

  // Verify before storing, so a typo fails now rather than at first use.
  const make = ctx.makeClient ?? ((o) => new LinkPilot(o));
  const baseUrl = flagString(ctx.argv.flags, "base-url");
  const me = await make({ apiKey: key, baseUrl }).me();

  const path = writeStored({ apiKey: key, baseUrl }, ctx.env);
  emit(
    ctx,
    `Logged in on the ${me.plan} plan. Key stored in ${path} (readable only by you).`,
    { ok: true, plan: me.plan, path },
  );
  return 0;
}

export async function cmdLogout(ctx: Ctx): Promise<number> {
  const removed = clearStored(ctx.env);
  emit(
    ctx,
    removed
      ? `Removed ${configPath(ctx.env)}.`
      : "No stored key to remove.",
    { removed },
  );
  if (ctx.env[ENV_VAR]) {
    ctx.err(`note: ${ENV_VAR} is still set in this shell and takes priority.`);
  }
  return 0;
}

export function describeError(e: unknown): string {
  if (e instanceof LinkPilotApiError) {
    if (e.needsUpgrade) return `${e.message}${e.upgradeUrl ? `\nUpgrade: ${e.upgradeUrl}` : ""}`;
    if (e.isDisabled) return "The LinkPilot API is not switched on for this deployment yet.";
    if (e.code === "unauthorized") return "That API key was rejected. Check it, or run \"linkpilot login\" again.";
    if (e.code === "rate_limited") {
      return `Rate limited. Try again in ${e.retryAfterSeconds ?? 60} seconds.`;
    }
    return e.message;
  }
  return e instanceof Error ? e.message : String(e);
}
