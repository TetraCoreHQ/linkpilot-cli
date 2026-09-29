/**
 * Where the API key lives.
 *
 * Order, highest priority first:
 *   1. `--key` on the command line  (scripts and CI that pass it explicitly)
 *   2. `LINKPILOT_API_KEY`          (the right answer for CI)
 *   3. the config file              (what `linkpilot login` writes)
 *
 * WHY A FILE AND NOT A KEYCHAIN. The plan named keytar. keytar is a native
 * module, it is archived upstream, and it fails to install on exactly the
 * machines a CLI most needs to work on. A 0600 file in the user's config
 * directory is the same posture as ~/.npmrc, ~/.aws/credentials and the
 * GitHub CLI's hosts.yml, with no build step and no native dependency. If a
 * real keychain is wanted later it can be layered in front of this without
 * changing any caller.
 *
 * The file is written with mode 0600 and the directory 0700. On Windows the
 * mode is advisory, so the key sits under %APPDATA%, which is already
 * per-user.
 */

import { chmodSync, mkdirSync, readFileSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { homedir, platform } from "node:os";
import { dirname, join } from "node:path";

export const API_KEY_PREFIX = "lp_live_";
export const ENV_VAR = "LINKPILOT_API_KEY";

export function configDir(env: NodeJS.ProcessEnv = process.env): string {
  if (env.LINKPILOT_CONFIG_DIR) return env.LINKPILOT_CONFIG_DIR;
  if (platform() === "win32") {
    return join(env.APPDATA ?? join(homedir(), "AppData", "Roaming"), "linkpilot");
  }
  if (platform() === "darwin") {
    return join(homedir(), "Library", "Application Support", "linkpilot");
  }
  return join(env.XDG_CONFIG_HOME ?? join(homedir(), ".config"), "linkpilot");
}

export function configPath(env: NodeJS.ProcessEnv = process.env): string {
  return join(configDir(env), "credentials.json");
}

export interface StoredCredentials {
  apiKey: string;
  baseUrl?: string;
}

export function readStored(env: NodeJS.ProcessEnv = process.env): StoredCredentials | null {
  const p = configPath(env);
  if (!existsSync(p)) return null;
  try {
    const parsed = JSON.parse(readFileSync(p, "utf8")) as Partial<StoredCredentials>;
    if (typeof parsed.apiKey !== "string" || !parsed.apiKey.startsWith(API_KEY_PREFIX)) return null;
    return { apiKey: parsed.apiKey, baseUrl: typeof parsed.baseUrl === "string" ? parsed.baseUrl : undefined };
  } catch {
    // A corrupt file is the same as no file; never crash the CLI over it.
    return null;
  }
}

export function writeStored(creds: StoredCredentials, env: NodeJS.ProcessEnv = process.env): string {
  const p = configPath(env);
  mkdirSync(dirname(p), { recursive: true, mode: 0o700 });
  // Write, THEN tighten, then verify: creating the file 0600 up front is not
  // portable, and leaving it world-readable for even a moment is the bug.
  writeFileSync(p, `${JSON.stringify(creds, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  try {
    chmodSync(p, 0o600);
    chmodSync(dirname(p), 0o700);
  } catch {
    // Windows: modes are advisory. %APPDATA% is already per-user.
  }
  return p;
}

export function clearStored(env: NodeJS.ProcessEnv = process.env): boolean {
  const p = configPath(env);
  if (!existsSync(p)) return false;
  rmSync(p, { force: true });
  return true;
}

export interface ResolvedKey {
  apiKey: string;
  source: "flag" | "env" | "file";
  baseUrl?: string;
}

export function resolveKey(
  flagKey: string | undefined,
  env: NodeJS.ProcessEnv = process.env,
): ResolvedKey | null {
  if (flagKey) return { apiKey: flagKey, source: "flag" };
  const fromEnv = env[ENV_VAR];
  if (fromEnv) return { apiKey: fromEnv, source: "env" };
  const stored = readStored(env);
  if (stored) return { apiKey: stored.apiKey, source: "file", baseUrl: stored.baseUrl };
  return null;
}

/**
 * Show enough of a key to recognise it, never enough to use it.
 * `lp_live_0123…cdef` — the prefix plus four characters at each end.
 */
export function maskKey(key: string): string {
  const body = key.startsWith(API_KEY_PREFIX) ? key.slice(API_KEY_PREFIX.length) : key;
  if (body.length <= 8) return `${API_KEY_PREFIX}${"*".repeat(body.length)}`;
  return `${API_KEY_PREFIX}${body.slice(0, 4)}…${body.slice(-4)}`;
}
