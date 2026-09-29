/**
 * @uselinkpilot/sdk — typed client for the LinkPilot API v1.
 *
 * Secrets are encrypted in YOUR process. LinkPilot receives ciphertext and no
 * key, and cannot decrypt what it stores. See `secrets.create`.
 */
export { LinkPilot, LinkPilotApiError, DEFAULT_BASE_URL, API_KEY_PREFIX } from "./client.js";
export type {
  ClientOptions,
  Me,
  Link,
  SecretSummary,
  CreatedSecret,
  CreateSecretInput,
  Paged,
} from "./client.js";
export { API_ERROR_CODES, ERROR_STATUS } from "./errors.js";
export type { ApiErrorCode } from "./errors.js";
export * as crypto from "./crypto.js";
