/**
 * Typed client for the LinkPilot API v1.
 *
 * The one thing worth reading before using this: **creating a secret returns
 * a URL that the server could not have produced.** LinkPilot never receives
 * the decryption key, so `secrets.create()` encrypts locally, sends only
 * ciphertext, and stitches the key onto the returned URL here. If you log or
 * store anything, store `shareUrl`; `secretUrl` without the fragment opens
 * nothing, for anyone, ever.
 */

import {
  encryptPayload,
  withKeyFragment,
  ENC_VERSION_V1,
  type EncryptResult,
} from "./crypto.js";
import { errorFromResponse, LinkPilotApiError } from "./errors.js";

export const DEFAULT_BASE_URL = "https://khiydxamyihofmtmgvjz.supabase.co/functions/v1/api-v1";
export const API_KEY_PREFIX = "lp_live_";

export interface ClientOptions {
  /** `lp_live_…`, from https://uselinkpilot.com/app/api-keys. Omit for public routes only. */
  apiKey?: string;
  baseUrl?: string;
  /** Defaults to the global `fetch`. Injectable for tests and proxies. */
  fetch?: typeof globalThis.fetch;
  /** Per-request timeout in ms. Default 20000. */
  timeoutMs?: number;
  /** Sent as User-Agent so we can tell clients apart in logs. */
  userAgent?: string;
}

/**
 * The shape `GET /me` actually returns, verified against production rather
 * than assumed. `plan` is an OBJECT, not a string: an earlier version of this
 * type said `plan: string` and the CLI duly printed "[object Object]".
 */
export interface Me {
  tenant: { id: string; name: string };
  plan: { slug: string; name: string };
  limits: {
    /** null means unlimited, for every one of these. */
    max_links: number | null;
    max_domains: number | null;
    max_active_secrets: number | null;
    secret_passphrase_enabled: boolean;
    analytics_history_days: number | null;
  };
  usage: { links: number; secrets: number; domains: number };
  /**
   * Worth surfacing rather than discarding: a client that backs off before
   * hitting the limit is better behaved than one that waits for a 429.
   */
  rate_limit: { limit_per_hour: number; remaining: number; reset_at: string };
}

export interface Link {
  id: string;
  short_url: string;
  url: string;
  slug: string;
  title: string | null;
  tags: string[];
  total_clicks: number;
  expires_at: string | null;
  created_at: string;
}

export interface SecretSummary {
  id: string;
  secret_url: string;
  status: string;
  expires_at: string | null;
  burn_after_read: boolean;
  burn_after_views: number | null;
  view_count: number;
  passphrase_protected: boolean;
  created_at: string;
}

export interface CreatedSecret {
  id: string;
  /** WITHOUT the key. Useless on its own. Kept for logging and reconciliation. */
  secretUrl: string;
  /** WITH the key. This is the only thing worth sending to a recipient. */
  shareUrl: string;
  /** The key half, if you need to transport it separately. */
  fragmentKey: string;
  expiresAt: string | null;
  burnAfterRead: boolean;
}

export interface CreateSecretInput {
  /** Plaintext. Encrypted here; never sent. */
  secret: string;
  /**
   * Pro and above. Mixed into the key AND sent as a SHA-256 hash so the
   * server can refuse to hand out the ciphertext at all. The raw passphrase
   * is never transmitted.
   */
  passphrase?: string;
  ttlSeconds?: number;
  burnAfterRead?: boolean;
}

export interface Paged<T> {
  data: T[];
  next_cursor: string | null;
}

async function sha256Hex(input: string): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(input),
  );
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export class LinkPilot {
  readonly #apiKey?: string;
  readonly #baseUrl: string;
  readonly #fetch: typeof globalThis.fetch;
  readonly #timeoutMs: number;
  readonly #userAgent: string;

  constructor(options: ClientOptions = {}) {
    if (options.apiKey !== undefined && !options.apiKey.startsWith(API_KEY_PREFIX)) {
      // Fail here rather than with a confusing 401 three calls later.
      throw new Error(`A LinkPilot API key starts with "${API_KEY_PREFIX}".`);
    }
    this.#apiKey = options.apiKey;
    this.#baseUrl = (options.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, "");
    this.#fetch = options.fetch ?? globalThis.fetch;
    this.#timeoutMs = options.timeoutMs ?? 20_000;
    this.#userAgent = options.userAgent ?? "@uselinkpilot/sdk";
  }

  async #request<T>(
    method: string,
    path: string,
    opts: { body?: unknown; query?: Record<string, string | number | undefined>; auth: boolean } = {
      auth: true,
    },
  ): Promise<T> {
    if (opts.auth && !this.#apiKey) {
      throw new Error("This call needs an API key. Construct LinkPilot({ apiKey }).");
    }

    const url = new URL(this.#baseUrl + path);
    for (const [k, v] of Object.entries(opts.query ?? {})) {
      if (v !== undefined) url.searchParams.set(k, String(v));
    }

    const headers: Record<string, string> = { "User-Agent": this.#userAgent };
    if (opts.auth) headers.Authorization = `Bearer ${this.#apiKey}`;
    if (opts.body !== undefined) headers["Content-Type"] = "application/json";

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.#timeoutMs);
    let res: Response;
    try {
      res = await this.#fetch(url.toString(), {
        method,
        headers,
        body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timer);
    }

    if (!res.ok) throw await errorFromResponse(res);
    if (res.status === 204) return undefined as T;
    return (await res.json()) as T;
  }

  /** Plan, limits and current usage for the key's workspace. */
  me(): Promise<Me> {
    return this.#request<Me>("GET", "/me", { auth: true });
  }

  readonly links = {
    create: (input: {
      url: string;
      slug?: string;
      domain?: string;
      title?: string;
      tags?: string[];
    }): Promise<Link> => this.#request<Link>("POST", "/links", { body: input, auth: true }),

    list: (opts: { limit?: number; cursor?: string } = {}): Promise<Paged<Link>> =>
      this.#request<Paged<Link>>("GET", "/links", { query: opts, auth: true }),

    get: (id: string): Promise<Link> =>
      this.#request<Link>("GET", `/links/${encodeURIComponent(id)}`, { auth: true }),

    delete: (id: string): Promise<void> =>
      this.#request<void>("DELETE", `/links/${encodeURIComponent(id)}`, { auth: true }),
  };

  readonly secrets = {
    /**
     * Encrypt locally, store the ciphertext, and return a link that works.
     *
     * The key exists only in this process until it is put in `shareUrl`.
     * There is no recovery path: if the share URL is lost the secret is gone,
     * including for LinkPilot.
     */
    create: async (input: CreateSecretInput): Promise<CreatedSecret> => {
      const sealed: EncryptResult = await encryptPayload(input.secret, input.passphrase);

      const body: Record<string, unknown> = {
        ciphertext: sealed.stored,
        enc_version: ENC_VERSION_V1,
      };
      if (input.ttlSeconds !== undefined) body.ttl_seconds = input.ttlSeconds;
      if (input.burnAfterRead !== undefined) body.burn_after_read = input.burnAfterRead;
      if (input.passphrase !== undefined) {
        // The hash, never the passphrase itself: it is half of the key.
        body.passphrase_hash = await sha256Hex(input.passphrase);
      }

      const res = await this.#request<{
        id: string;
        secret_url: string;
        expires_at: string | null;
        burn_after_read: boolean;
      }>("POST", "/secrets", { body, auth: true });

      return {
        id: res.id,
        secretUrl: res.secret_url,
        shareUrl: withKeyFragment(res.secret_url, sealed.fragmentKey),
        fragmentKey: sealed.fragmentKey,
        expiresAt: res.expires_at,
        burnAfterRead: res.burn_after_read,
      };
    },

    /** Metadata only. No route returns a payload or a ciphertext. */
    list: (opts: { limit?: number; cursor?: string } = {}): Promise<Paged<SecretSummary>> =>
      this.#request<Paged<SecretSummary>>("GET", "/secrets", { query: opts, auth: true }),

    revoke: (id: string): Promise<void> =>
      this.#request<void>("DELETE", `/secrets/${encodeURIComponent(id)}`, { auth: true }),
  };

  /**
   * No-key routes, backed by the same anonymous pool as the website's free
   * tools. They need a Cloudflare Turnstile token, which a headless client
   * cannot mint, so these are for surfaces that can show a human a web page.
   */
  readonly anonymous = {
    createLink: (input: {
      url: string;
      clientId: string;
      turnstileToken: string;
      ttlSeconds?: number;
    }): Promise<{ id: string; short_url: string; expires_at: string | null; claim_token: string }> =>
      this.#request("POST", "/public/links", {
        auth: false,
        body: {
          url: input.url,
          client_id: input.clientId,
          turnstile_token: input.turnstileToken,
          ...(input.ttlSeconds === undefined ? {} : { ttl_seconds: input.ttlSeconds }),
        },
      }),

    createSecret: async (input: {
      secret: string;
      clientId: string;
      turnstileToken: string;
      ttlSeconds?: number;
    }): Promise<CreatedSecret> => {
      // Anonymous secrets never take a passphrase, so always the v1 shape.
      const sealed = await encryptPayload(input.secret);
      const res = await this.#request<{
        id: string;
        secret_url: string;
        expires_at: string | null;
        burn_after_read: boolean;
      }>("POST", "/public/secrets", {
        auth: false,
        body: {
          ciphertext: sealed.stored,
          enc_version: ENC_VERSION_V1,
          client_id: input.clientId,
          turnstile_token: input.turnstileToken,
          ...(input.ttlSeconds === undefined ? {} : { ttl_seconds: input.ttlSeconds }),
        },
      });
      return {
        id: res.id,
        secretUrl: res.secret_url,
        shareUrl: withKeyFragment(res.secret_url, sealed.fragmentKey),
        fragmentKey: sealed.fragmentKey,
        expiresAt: res.expires_at,
        burnAfterRead: res.burn_after_read,
      };
    },
  };
}

export { LinkPilotApiError };
