/**
 * Client-side encryption for LinkPilot secret links.
 *
 * WHY THIS EXISTS IN THE SDK AT ALL. The LinkPilot API will not accept a
 * plaintext secret: `POST /secrets` requires `ciphertext` and `enc_version: 1`
 * and rejects a `payload` field outright. That is not an inconvenience to work
 * around, it is the product guarantee — LinkPilot never receives the key and
 * cannot decrypt what it stores. Any client that wants to create a secret has
 * to do the encryption itself, so the SDK does it once, correctly, rather than
 * leaving four downstream clients to each get it wrong.
 *
 * THIS IS ONE OF THREE IMPLEMENTATIONS of the format: the LinkPilot web
 * application, the reveal page served at the edge, and this package. Three
 * implementations of one format is a drift risk, so it is pinned the only way
 * that actually works: `test/crypto.vectors.test.ts` runs the SAME committed
 * known-answer vectors the other two are built against. If any of them ever
 * disagree about a byte, those tests fail.
 *
 * Wire format, specified at https://uselinkpilot.com/developers :
 *
 *   no passphrase   v1.<b64u(iv12)>.<b64u(ct||tag)>          fragment #k=<b64u(K32)>
 *   with passphrase v1p.<b64u(salt16)>.<b64u(iv12)>.<b64u(ct||tag)>
 *                   fragment #k=<b64u(L32)>
 *                   K = HKDF-SHA256(
 *                         ikm  = L || PBKDF2-SHA256(passphrase, salt, 210000, 32),
 *                         salt = salt,
 *                         info = "linkpilot-secret-v1",
 *                         len  = 32)
 *
 * Neither the link alone nor the passphrase alone opens a v1p secret.
 *
 * Runtime: WebCrypto only (`globalThis.crypto.subtle`), so this works
 * unchanged in Node 20+, Deno, Bun, browsers and edge runtimes. No
 * dependencies, deliberately: a crypto path is the last place to accept
 * supply-chain surface.
 */

export const ENC_VERSION_LEGACY = 0;
export const ENC_VERSION_V1 = 1;

export const V1_PREFIX = "v1";
export const V1P_PREFIX = "v1p";

export const IV_BYTES = 12;
export const SALT_BYTES = 16;
export const KEY_BYTES = 32;
export const TAG_BITS = 128;
export const PBKDF2_ITERATIONS = 210_000;
export const HKDF_INFO = "linkpilot-secret-v1";
export const HKDF_ATTACHMENT_INFO = "linkpilot-attachment-v1";
export const FRAGMENT_KEY_PARAM = "k";

export type SecretCryptoErrorCode =
  | "unsupported_format"
  | "missing_key"
  | "bad_key"
  | "passphrase_required"
  | "decrypt_failed";

export class SecretCryptoError extends Error {
  readonly code: SecretCryptoErrorCode;
  constructor(code: SecretCryptoErrorCode, message?: string) {
    super(message ?? code);
    this.name = "SecretCryptoError";
    this.code = code;
  }
}

function subtle(): SubtleCrypto {
  const c = (globalThis as { crypto?: Crypto }).crypto;
  if (!c?.subtle) {
    throw new SecretCryptoError(
      "unsupported_format",
      "WebCrypto is unavailable. Node 20+, Deno, Bun or a browser is required.",
    );
  }
  return c.subtle;
}

function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  (globalThis as unknown as { crypto: Crypto }).crypto.getRandomValues(out);
  return out;
}

/** Views a Uint8Array as a plain ArrayBuffer for WebCrypto, without copying. */
function buf(b: Uint8Array): ArrayBuffer {
  return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) as ArrayBuffer;
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

/* -------------------------------------------------------------------------- */
/*                                  base64url                                 */
/* -------------------------------------------------------------------------- */

const B64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

export function toBase64Url(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i];
    const b = i + 1 < bytes.length ? bytes[i + 1] : undefined;
    const c = i + 2 < bytes.length ? bytes[i + 2] : undefined;
    out += B64URL_ALPHABET[a >> 2];
    out += B64URL_ALPHABET[((a & 3) << 4) | ((b ?? 0) >> 4)];
    if (b === undefined) break;
    out += B64URL_ALPHABET[((b & 15) << 2) | ((c ?? 0) >> 6)];
    if (c === undefined) break;
    out += B64URL_ALPHABET[c & 63];
  }
  return out;
}

function code(ch: string): number {
  const i = B64URL_ALPHABET.indexOf(ch);
  return i;
}

export function isBase64Url(text: unknown): boolean {
  if (typeof text !== "string" || text.length === 0) return false;
  if (text.length % 4 === 1) return false;
  for (const ch of text) if (code(ch) < 0) return false;
  return true;
}

/**
 * ONE DELIBERATE DIFFERENCE from the web app's copy, recorded here because a
 * silent divergence between two implementations of one format is exactly what
 * the vector tests exist to prevent.
 *
 * The web app's `fromBase64Url` only type-checks and otherwise decodes
 * garbage-in, garbage-out. This one rejects malformed input outright. Every
 * real call site in BOTH implementations guards with `isBase64Url` first or
 * length-checks the result, so no reachable behaviour differs; this is just
 * the safer default for a function a downstream client might call directly.
 *
 * The empty string decodes to an empty array in both, because that is correct
 * base64url and a legitimate value.
 */
export function fromBase64Url(text: string): Uint8Array {
  if (text === "") return new Uint8Array(0);
  if (!isBase64Url(text)) throw new SecretCryptoError("bad_key", "Not base64url.");
  const n = text.length;
  const full = Math.floor(n / 4);
  const rem = n % 4;
  const outLen = full * 3 + (rem === 2 ? 1 : rem === 3 ? 2 : 0);
  const out = new Uint8Array(outLen);
  let o = 0;
  for (let i = 0; i < full * 4; i += 4) {
    const v =
      (code(text[i]) << 18) | (code(text[i + 1]) << 12) | (code(text[i + 2]) << 6) | code(text[i + 3]);
    out[o++] = (v >> 16) & 255;
    out[o++] = (v >> 8) & 255;
    out[o++] = v & 255;
  }
  if (rem === 2) {
    const v = (code(text[n - 2]) << 18) | (code(text[n - 1]) << 12);
    out[o++] = (v >> 16) & 255;
  } else if (rem === 3) {
    const v = (code(text[n - 3]) << 18) | (code(text[n - 2]) << 12) | (code(text[n - 1]) << 6);
    out[o++] = (v >> 16) & 255;
    out[o++] = (v >> 8) & 255;
  }
  return out;
}

/* -------------------------------------------------------------------------- */
/*                               parse / derive                               */
/* -------------------------------------------------------------------------- */

export interface ParsedLegacy {
  version: typeof ENC_VERSION_LEGACY;
  plaintext: string;
}
export interface ParsedV1 {
  version: typeof ENC_VERSION_V1;
  withPassphrase: boolean;
  salt: Uint8Array | null;
  iv: Uint8Array;
  ciphertext: Uint8Array;
}
export type ParsedStored = ParsedLegacy | ParsedV1;

function decodeExact(text: string, bytes: number): Uint8Array | null {
  try {
    const b = fromBase64Url(text);
    return b.length === bytes ? b : null;
  } catch {
    return null;
  }
}
function decodeAtLeast(text: string, bytes: number): Uint8Array | null {
  try {
    const b = fromBase64Url(text);
    return b.length >= bytes ? b : null;
  } catch {
    return null;
  }
}

/**
 * Anything that is not a well-formed v1 value parses as LEGACY PLAINTEXT, not
 * as an error. That is deliberate and matches the server: a secret created
 * before encryption shipped is a plain string, and a v1-lookalike that fails
 * to decode must not be mistaken for ciphertext.
 */
export function parseStored(stored: string): ParsedStored {
  if (typeof stored !== "string" || stored.length === 0) {
    return { version: ENC_VERSION_LEGACY, plaintext: typeof stored === "string" ? stored : "" };
  }
  const parts = stored.split(".");
  if (parts[0] === V1_PREFIX && parts.length === 3) {
    const iv = decodeExact(parts[1], IV_BYTES);
    const ct = decodeAtLeast(parts[2], TAG_BITS / 8);
    if (iv && ct) return { version: ENC_VERSION_V1, withPassphrase: false, salt: null, iv, ciphertext: ct };
    return { version: ENC_VERSION_LEGACY, plaintext: stored };
  }
  if (parts[0] === V1P_PREFIX && parts.length === 4) {
    const salt = decodeExact(parts[1], SALT_BYTES);
    const iv = decodeExact(parts[2], IV_BYTES);
    const ct = decodeAtLeast(parts[3], TAG_BITS / 8);
    if (salt && iv && ct) return { version: ENC_VERSION_V1, withPassphrase: true, salt, iv, ciphertext: ct };
    return { version: ENC_VERSION_LEGACY, plaintext: stored };
  }
  return { version: ENC_VERSION_LEGACY, plaintext: stored };
}

export function isEncrypted(stored: string): boolean {
  return parseStored(stored).version === ENC_VERSION_V1;
}

async function importAesKey(raw: Uint8Array): Promise<CryptoKey> {
  return subtle().importKey("raw", buf(raw), { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

export async function stretchPassphrase(passphrase: string, salt: Uint8Array): Promise<Uint8Array> {
  const material = await subtle().importKey(
    "raw",
    buf(new TextEncoder().encode(passphrase)),
    { name: "PBKDF2" },
    false,
    ["deriveBits"],
  );
  const bits = await subtle().deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: buf(salt), iterations: PBKDF2_ITERATIONS },
    material,
    KEY_BYTES * 8,
  );
  return new Uint8Array(bits);
}

export async function deriveKeyWithPassphrase(
  linkHalf: Uint8Array,
  passphrase: string,
  salt: Uint8Array,
): Promise<Uint8Array> {
  const stretched = await stretchPassphrase(passphrase, salt);
  const hkdf = await subtle().importKey("raw", buf(concat(linkHalf, stretched)), "HKDF", false, [
    "deriveBits",
  ]);
  const bits = await subtle().deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: buf(salt),
      info: buf(new TextEncoder().encode(HKDF_INFO)),
    },
    hkdf,
    KEY_BYTES * 8,
  );
  return new Uint8Array(bits);
}

/* -------------------------------------------------------------------------- */
/*                               encrypt / decrypt                            */
/* -------------------------------------------------------------------------- */

export interface EncryptResult {
  /** Send as `ciphertext` with `enc_version: 1`. */
  stored: string;
  /** Append to the share URL as `#k=…`. NEVER send this to the server. */
  fragmentKey: string;
}

export async function encryptPayload(
  plaintext: string,
  passphrase?: string | null,
): Promise<EncryptResult> {
  const data = new TextEncoder().encode(plaintext ?? "");
  const iv = randomBytes(IV_BYTES);
  const usePassphrase = typeof passphrase === "string" && passphrase.length > 0;

  if (!usePassphrase) {
    const k = randomBytes(KEY_BYTES);
    const ct = new Uint8Array(
      await subtle().encrypt({ name: "AES-GCM", iv: buf(iv), tagLength: TAG_BITS }, await importAesKey(k), buf(data)),
    );
    return { stored: `${V1_PREFIX}.${toBase64Url(iv)}.${toBase64Url(ct)}`, fragmentKey: toBase64Url(k) };
  }

  const salt = randomBytes(SALT_BYTES);
  const linkHalf = randomBytes(KEY_BYTES);
  const k = await deriveKeyWithPassphrase(linkHalf, passphrase as string, salt);
  const ct = new Uint8Array(
    await subtle().encrypt({ name: "AES-GCM", iv: buf(iv), tagLength: TAG_BITS }, await importAesKey(k), buf(data)),
  );
  return {
    stored: `${V1P_PREFIX}.${toBase64Url(salt)}.${toBase64Url(iv)}.${toBase64Url(ct)}`,
    fragmentKey: toBase64Url(linkHalf),
  };
}

/** The content key K, from the link fragment and, for v1p, the passphrase. */
export async function resolveContentKey(
  stored: string,
  fragmentKey: string | null | undefined,
  passphrase?: string | null,
): Promise<Uint8Array> {
  const parsed = parseStored(stored);
  if (parsed.version === ENC_VERSION_LEGACY) throw new SecretCryptoError("unsupported_format");
  if (fragmentKey == null || fragmentKey === "") throw new SecretCryptoError("missing_key");
  if (!isBase64Url(fragmentKey)) throw new SecretCryptoError("bad_key");
  const half = fromBase64Url(fragmentKey);
  if (half.length !== KEY_BYTES) throw new SecretCryptoError("bad_key");
  if (parsed.withPassphrase) {
    if (typeof passphrase !== "string") throw new SecretCryptoError("passphrase_required");
    return deriveKeyWithPassphrase(half, passphrase, parsed.salt as Uint8Array);
  }
  return half;
}

export async function decryptPayload(
  stored: string,
  fragmentKey: string | null | undefined,
  passphrase?: string | null,
): Promise<string> {
  const parsed = parseStored(stored);
  if (parsed.version === ENC_VERSION_LEGACY) throw new SecretCryptoError("unsupported_format");
  const key = await importAesKey(await resolveContentKey(stored, fragmentKey, passphrase));
  try {
    const plain = await subtle().decrypt(
      { name: "AES-GCM", iv: buf(parsed.iv), tagLength: TAG_BITS },
      key,
      buf(parsed.ciphertext),
    );
    return new TextDecoder().decode(plain);
  } catch {
    // A wrong key, a wrong passphrase and a tampered ciphertext are
    // deliberately indistinguishable.
    throw new SecretCryptoError("decrypt_failed");
  }
}

/* -------------------------------------------------------------------------- */
/*                                 attachments                                */
/* -------------------------------------------------------------------------- */

/**
 * K_att = HKDF-SHA256(K, salt = "", info = "linkpilot-attachment-v1").
 *
 * A derived key rather than K itself: reusing one AES-GCM key across two
 * plaintexts is only safe while no IV ever repeats, and separating them means
 * a mistake in one path cannot weaken the other.
 */
export async function deriveAttachmentKey(contentKey: Uint8Array): Promise<Uint8Array> {
  const hkdf = await subtle().importKey("raw", buf(contentKey), "HKDF", false, ["deriveBits"]);
  const bits = await subtle().deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(0),
      info: buf(new TextEncoder().encode(HKDF_ATTACHMENT_INFO)),
    },
    hkdf,
    KEY_BYTES * 8,
  );
  return new Uint8Array(bits);
}

/** Stored attachment object is `iv || ct||tag` as RAW BYTES, not base64. */
export async function encryptAttachment(bytes: Uint8Array, attachmentKey: Uint8Array): Promise<Uint8Array> {
  const iv = randomBytes(IV_BYTES);
  const ct = new Uint8Array(
    await subtle().encrypt(
      { name: "AES-GCM", iv: buf(iv), tagLength: TAG_BITS },
      await importAesKey(attachmentKey),
      buf(bytes),
    ),
  );
  return concat(iv, ct);
}

export async function decryptAttachment(stored: Uint8Array, attachmentKey: Uint8Array): Promise<Uint8Array> {
  if (stored.length < IV_BYTES + TAG_BITS / 8) throw new SecretCryptoError("unsupported_format");
  try {
    const plain = await subtle().decrypt(
      { name: "AES-GCM", iv: buf(stored.subarray(0, IV_BYTES)), tagLength: TAG_BITS },
      await importAesKey(attachmentKey),
      buf(stored.subarray(IV_BYTES)),
    );
    return new Uint8Array(plain);
  } catch {
    throw new SecretCryptoError("decrypt_failed");
  }
}

/* -------------------------------------------------------------------------- */
/*                                  fragments                                 */
/* -------------------------------------------------------------------------- */

export function buildKeyFragment(fragmentKey: string): string {
  return `#${FRAGMENT_KEY_PARAM}=${fragmentKey}`;
}

/**
 * Attach the key to a share URL. A falsy key returns the URL untouched, and
 * any existing fragment is replaced rather than appended to, because two `#`
 * in one URL silently swallow the key.
 */
export function withKeyFragment(url: string, fragmentKey: string | null | undefined): string {
  if (typeof fragmentKey !== "string" || fragmentKey.length === 0) return url;
  const hash = url.indexOf("#");
  return (hash < 0 ? url : url.slice(0, hash)) + buildKeyFragment(fragmentKey);
}

export function readFragmentKey(hash: string | null | undefined): string | null {
  if (typeof hash !== "string" || hash.length === 0) return null;
  const raw = hash.charAt(0) === "#" ? hash.slice(1) : hash;
  for (const pair of raw.split("&")) {
    const eq = pair.indexOf("=");
    if (eq < 0) continue;
    if (pair.slice(0, eq) !== FRAGMENT_KEY_PARAM) continue;
    const v = pair.slice(eq + 1);
    return v.length > 0 ? v : null;
  }
  return null;
}
