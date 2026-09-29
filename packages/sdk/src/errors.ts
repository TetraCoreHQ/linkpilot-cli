/**
 * The API's error model, mirrored so callers can branch on a code instead of
 * matching on message text.
 *
 * Kept in step with the API's own error model, documented at
 * https://uselinkpilot.com/developers. A test pins the list, because a code
 * the SDK does not know about would otherwise fall through to a generic
 * error and lose the thing the caller most needs: whether to retry, upgrade,
 * or stop.
 */

export const API_ERROR_CODES = [
  "unauthorized",
  "disabled",
  "invalid_request",
  "not_found",
  "plan_limit",
  "pro_required",
  "rate_limited",
  "internal_error",
] as const;

export type ApiErrorCode = (typeof API_ERROR_CODES)[number];

export const ERROR_STATUS: Record<ApiErrorCode, number> = {
  unauthorized: 401,
  disabled: 503,
  invalid_request: 400,
  not_found: 404,
  plan_limit: 402,
  pro_required: 402,
  rate_limited: 429,
  internal_error: 500,
};

export interface ApiErrorBody {
  error: { code: string; message?: string; upgrade_url?: string };
}

export class LinkPilotApiError extends Error {
  readonly code: ApiErrorCode | "unknown_error";
  readonly status: number;
  /** Present on plan_limit / pro_required. */
  readonly upgradeUrl?: string;
  /** Seconds to wait, from the Retry-After header, on rate_limited. */
  readonly retryAfterSeconds?: number;
  /** The raw body, for anything the SDK has not modelled. */
  readonly body?: unknown;

  constructor(args: {
    code: ApiErrorCode | "unknown_error";
    status: number;
    message: string;
    upgradeUrl?: string;
    retryAfterSeconds?: number;
    body?: unknown;
  }) {
    super(args.message);
    this.name = "LinkPilotApiError";
    this.code = args.code;
    this.status = args.status;
    this.upgradeUrl = args.upgradeUrl;
    this.retryAfterSeconds = args.retryAfterSeconds;
    this.body = args.body;
  }

  /** Worth trying again unchanged: a rate limit or a transient server fault. */
  get isRetryable(): boolean {
    return this.code === "rate_limited" || this.status >= 500;
  }

  /**
   * The API is deployed but switched off for this deployment. Distinct from a
   * server fault: retrying will not help until the flag is turned on.
   */
  get isDisabled(): boolean {
    return this.code === "disabled";
  }

  /** The workspace's plan is the blocker, not the request. */
  get needsUpgrade(): boolean {
    return this.code === "plan_limit" || this.code === "pro_required";
  }
}

function isKnownCode(v: unknown): v is ApiErrorCode {
  return typeof v === "string" && (API_ERROR_CODES as readonly string[]).includes(v);
}

/** Build an error from a non-2xx response, tolerating a non-JSON body. */
export async function errorFromResponse(res: Response): Promise<LinkPilotApiError> {
  let body: unknown;
  let raw = "";
  try {
    raw = await res.text();
    body = raw ? JSON.parse(raw) : undefined;
  } catch {
    body = undefined;
  }

  const envelope = (body as ApiErrorBody | undefined)?.error;
  const code = isKnownCode(envelope?.code) ? envelope.code : "unknown_error";

  const retryAfter = res.headers.get("retry-after");
  const retryAfterSeconds =
    retryAfter && /^\d+$/.test(retryAfter) ? Number(retryAfter) : undefined;

  const message =
    envelope?.message ||
    // Never echo a raw HTML error page into an exception message.
    (code === "unknown_error"
      ? `LinkPilot API returned HTTP ${res.status}`
      : `LinkPilot API error: ${code}`);

  return new LinkPilotApiError({
    code,
    status: res.status,
    message,
    upgradeUrl: envelope?.upgrade_url,
    retryAfterSeconds,
    body,
  });
}
