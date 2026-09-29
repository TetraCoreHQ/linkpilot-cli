/**
 * Known-answer tests against the SAME committed vectors the LinkPilot web app
 * uses (`src/lib/__tests__/fixtures/secretCryptoVectors.json` in uselinkpilot).
 *
 * This is the only thing that makes a second implementation of a crypto format
 * safe to ship. There are now three implementations of this wire format: the
 * web app, the Cloudflare worker's inline copy, and this SDK. Code review does
 * not catch a one-byte divergence in a KDF; a vector that stops decrypting
 * does, immediately.
 *
 * A vector failing here means one of two things, and both are serious:
 *   - this port is wrong, and every secret it creates is unreadable by the
 *     LinkPilot reveal page; or
 *   - the FORMAT changed upstream, and every secret already stored is now
 *     unreadable. Legacy rows are never re-encrypted, so that is unrecoverable
 *     data loss, not a migration.
 *
 * Either way, do not "fix" this by regenerating the fixture.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import {
  decryptPayload,
  encryptPayload,
  parseStored,
  isEncrypted,
  toBase64Url,
  fromBase64Url,
  resolveContentKey,
  SecretCryptoError,
  PBKDF2_ITERATIONS,
  HKDF_INFO,
  IV_BYTES,
  SALT_BYTES,
  KEY_BYTES,
  ENC_VERSION_V1,
  ENC_VERSION_LEGACY,
} from "../src/crypto.js";

const here = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(
  readFileSync(resolve(here, "fixtures/secretCryptoVectors.json"), "utf8"),
) as {
  hkdfInfo: string;
  pbkdf2Iterations: number;
  ivBytes: number;
  saltBytes: number;
  keyBytes: number;
  vectors: Array<{
    name: string;
    plaintext: string;
    passphrase: string | null;
    stored: string;
    fragmentKey: string;
  }>;
  legacyPlaintexts: string[];
};

describe("the format constants match the fixture", () => {
  it("pins the cost parameters and sizes", () => {
    // If any of these drift, every existing secret stops opening.
    expect(HKDF_INFO).toBe(vectors.hkdfInfo);
    expect(PBKDF2_ITERATIONS).toBe(vectors.pbkdf2Iterations);
    expect(IV_BYTES).toBe(vectors.ivBytes);
    expect(SALT_BYTES).toBe(vectors.saltBytes);
    expect(KEY_BYTES).toBe(vectors.keyBytes);
  });
});

describe("known-answer vectors from the web app", () => {
  it("has vectors covering both shapes", () => {
    expect(vectors.vectors.length).toBeGreaterThanOrEqual(4);
    expect(vectors.vectors.some((v) => v.stored.startsWith("v1."))).toBe(true);
    expect(vectors.vectors.some((v) => v.stored.startsWith("v1p."))).toBe(true);
  });

  for (const v of vectors.vectors) {
    it(`decrypts "${v.name}" produced by the web app`, async () => {
      const out = await decryptPayload(v.stored, v.fragmentKey, v.passphrase);
      expect(out).toBe(v.plaintext);
    });

    it(`parses "${v.name}" as v1, not as legacy plaintext`, () => {
      const p = parseStored(v.stored);
      expect(p.version).toBe(ENC_VERSION_V1);
      expect(isEncrypted(v.stored)).toBe(true);
      if (p.version === ENC_VERSION_V1) {
        expect(p.withPassphrase).toBe(Boolean(v.passphrase));
        expect(p.iv.length).toBe(IV_BYTES);
        if (v.passphrase) expect(p.salt?.length).toBe(SALT_BYTES);
      }
    });

    it(`refuses "${v.name}" without its key`, async () => {
      await expect(decryptPayload(v.stored, null, v.passphrase)).rejects.toBeInstanceOf(SecretCryptoError);
    });

    if (v.passphrase) {
      it(`refuses "${v.name}" with the link but no passphrase`, async () => {
        // The point of v1p: the link alone is not enough.
        await expect(decryptPayload(v.stored, v.fragmentKey)).rejects.toBeInstanceOf(SecretCryptoError);
      });

      it(`refuses "${v.name}" with the wrong passphrase`, async () => {
        await expect(
          decryptPayload(v.stored, v.fragmentKey, `${v.passphrase}x`),
        ).rejects.toBeInstanceOf(SecretCryptoError);
      });
    }
  }
});

describe("legacy values are never mistaken for ciphertext", () => {
  it("parses every committed legacy sample as plaintext", () => {
    // Includes v1-lookalikes that must NOT be treated as encrypted.
    for (const p of vectors.legacyPlaintexts) {
      const parsed = parseStored(p);
      expect(parsed.version).toBe(ENC_VERSION_LEGACY);
      expect(isEncrypted(p)).toBe(false);
    }
  });

  it("refuses to decrypt a legacy value rather than returning junk", async () => {
    await expect(decryptPayload("hunter2", "x".repeat(43))).rejects.toBeInstanceOf(SecretCryptoError);
  });
});

describe("this SDK's own output is readable by the same rules", () => {
  it("round-trips without a passphrase", async () => {
    const { stored, fragmentKey } = await encryptPayload("db password: hunter2");
    expect(stored.startsWith("v1.")).toBe(true);
    expect(stored).not.toContain(fragmentKey);
    expect(await decryptPayload(stored, fragmentKey)).toBe("db password: hunter2");
  });

  it("round-trips with a passphrase and needs both halves", async () => {
    const { stored, fragmentKey } = await encryptPayload("vpn.conf", "correct horse");
    expect(stored.startsWith("v1p.")).toBe(true);
    expect(await decryptPayload(stored, fragmentKey, "correct horse")).toBe("vpn.conf");
    await expect(decryptPayload(stored, fragmentKey)).rejects.toBeInstanceOf(SecretCryptoError);
  });

  it("round-trips unicode, emoji and a payload full of dots", async () => {
    // Dots are the format's own separator, so a payload of dots is the case
    // most likely to break a naive parser.
    for (const s of ["héllo wörld", "🔐🗝️ combining é", "....v1.p...", "", "a".repeat(10_000)]) {
      const { stored, fragmentKey } = await encryptPayload(s);
      expect(await decryptPayload(stored, fragmentKey)).toBe(s);
    }
  });

  it("uses a fresh key and IV every time", async () => {
    const a = await encryptPayload("same");
    const b = await encryptPayload("same");
    expect(a.stored).not.toBe(b.stored);
    expect(a.fragmentKey).not.toBe(b.fragmentKey);
  });

  it("emits base64url with no padding and no + or /", async () => {
    const { stored, fragmentKey } = await encryptPayload("x", "p");
    for (const part of [...stored.split(".").slice(1), fragmentKey]) {
      expect(part).not.toContain("=");
      expect(part).not.toContain("+");
      expect(part).not.toContain("/");
    }
  });
});

describe("resolveContentKey", () => {
  it("returns the raw fragment key for a v1 secret", async () => {
    const { stored, fragmentKey } = await encryptPayload("x");
    const k = await resolveContentKey(stored, fragmentKey);
    expect(Array.from(k)).toEqual(Array.from(fromBase64Url(fragmentKey)));
  });

  it("returns a DERIVED key for a v1p secret, not the fragment key", async () => {
    const { stored, fragmentKey } = await encryptPayload("x", "phrase");
    const k = await resolveContentKey(stored, fragmentKey, "phrase");
    expect(Array.from(k)).not.toEqual(Array.from(fromBase64Url(fragmentKey)));
    expect(k.length).toBe(KEY_BYTES);
  });
});

describe("base64url", () => {
  it("round-trips every length from 0 to 64 and all byte values", () => {
    for (let n = 0; n <= 64; n++) {
      const b = new Uint8Array(n).map((_, i) => (i * 7 + n) & 255);
      expect(Array.from(fromBase64Url(toBase64Url(b)))).toEqual(Array.from(b));
    }
    const all = new Uint8Array(256).map((_, i) => i);
    expect(Array.from(fromBase64Url(toBase64Url(all)))).toEqual(Array.from(all));
  });

  it("decodes the empty string to an empty array, as the web app does", () => {
    // This port is deliberately stricter than the web app on MALFORMED input;
    // the empty string must still behave identically in both.
    expect(Array.from(fromBase64Url(""))).toEqual([]);
    expect(toBase64Url(new Uint8Array(0))).toBe("");
  });

  it("rejects padding, whitespace and non-alphabet characters", () => {
    for (const bad of ["YQ==", "a b", "a+b", "a/b", "a\nb"]) {
      expect(() => fromBase64Url(bad)).toThrow(SecretCryptoError);
    }
  });
});
