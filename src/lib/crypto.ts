import "server-only";

/**
 * crypto.ts — Optional AES-256-GCM field-level encryption
 *
 * ─── PURPOSE ─────────────────────────────────────────────────────────────────
 *
 *  Provides encrypt / decrypt / hashForSearch helpers for sensitive database
 *  fields (e.g. email, name, phone). When the toggle is OFF the functions are
 *  pure pass-through — zero CPU overhead, no code-path changes needed at the
 *  call site.
 *
 *  Toggle:
 *    AUTH_FIELD_ENCRYPTION=true   → AES-256-GCM encryption active
 *    AUTH_FIELD_ENCRYPTION=false  → passthrough (default)
 *
 * ─── HOW IT WORKS ────────────────────────────────────────────────────────────
 *
 *  encrypt(plain)        → iv(12b) + authTag(16b) + ciphertext  →  base64
 *  decrypt(base64)       → reverses the above
 *  hashForSearch(value)  → HMAC-SHA256(value) → base64
 *
 *  hashForSearch is used for SEARCHABLE encrypted fields (e.g. email).
 *  Because AES-GCM uses a random IV, the same email encrypts differently every
 *  time, so you can't do  WHERE email = ?  on the ciphertext.
 *  Instead, store a deterministic HMAC beside it and query that:
 *
 *    emailHash = hashForSearch(email)  ← indexed, searchable
 *    email     = encrypt(email)        ← encrypted at rest
 *
 * ─── ALGORITHM ───────────────────────────────────────────────────────────────
 *
 *  AES-256-GCM
 *    - 256-bit key (32 raw bytes, base64-encoded in env)
 *    - 96-bit random IV per encryption (GCM best practice)
 *    - 128-bit authentication tag → detects tampering
 *    - No padding needed (stream cipher mode)
 *
 * ─── GENERATE KEY ────────────────────────────────────────────────────────────
 *
 *  openssl rand -base64 32
 *
 *  Store the output as ENCRYPTION_KEY in .env.local
 *
 * ─── SECURITY NOTES ──────────────────────────────────────────────────────────
 *
 *  OWASP A02 Cryptographic Failures:
 *    - Key never logged or returned to client
 *    - GCM authentication tag prevents ciphertext tampering
 *    - HMAC key is the same ENCRYPTION_KEY (separate keys are better in
 *      very high-security contexts; add HMAC_KEY env var if needed)
 *
 *  Key rotation: to rotate keys, re-encrypt existing rows with the new key
 *  before changing the env var. A migration script pattern is recommended.
 *
 * ─── USAGE ───────────────────────────────────────────────────────────────────
 *
 *  import { encrypt, decrypt, hashForSearch } from "@/lib/crypto";
 *
 *  // Writing to DB
 *  await db.user.create({
 *    data: {
 *      email:     encrypt(emailStr),
 *      emailHash: hashForSearch(emailStr),  // for WHERE lookups
 *      name:      encrypt(nameStr),
 *    },
 *  });
 *
 *  // Reading from DB
 *  const user = await db.user.findFirst({ where: { emailHash: hashForSearch(email) } });
 *  const displayEmail = decrypt(user.email);
 */

import crypto from "node:crypto";
import { AUTH_FRAMEWORK_CONFIG } from "@/lib/auth/framework-config";

// ─── Constants ────────────────────────────────────────────────────────────────

const ALGORITHM      = "aes-256-gcm";
const IV_LENGTH      = 12;  // 96-bit IV — GCM standard
const AUTH_TAG_LEN   = 16;  // 128-bit authentication tag
const KEY_BYTE_LEN   = 32;  // 256-bit key

// Layout of the encoded blob: [iv(12)] [tag(16)] [ciphertext(n)]
const IV_START       = 0;
const TAG_START      = IV_LENGTH;
const CT_START       = IV_LENGTH + AUTH_TAG_LEN;

// ─── Key resolution ───────────────────────────────────────────────────────────

function resolveMasterKey(): Buffer {
  const raw = process.env.ENCRYPTION_KEY;
  if (!raw) {
    throw new Error(
      "[crypto] ENCRYPTION_KEY is not set. " +
      "Generate one with: openssl rand -base64 32"
    );
  }
  const key = Buffer.from(raw, "base64");
  if (key.length !== KEY_BYTE_LEN) {
    throw new Error(
      `[crypto] ENCRYPTION_KEY must decode to exactly ${KEY_BYTE_LEN} bytes (256-bit). ` +
      `Got ${key.length} bytes. Re-generate with: openssl rand -base64 32`
    );
  }
  return key;
}

/**
 * Derive a purpose-specific subkey from the master key using HKDF-SHA256.
 *
 * Using the same raw key for both AES-GCM encryption and HMAC-SHA256 hashing
 * is not recommended — cross-protocol key reuse can leak information about the
 * key material in theory. HKDF derives two cryptographically independent keys
 * from one master key, one per purpose.
 *
 * No new env var needed — ENCRYPTION_KEY remains the single secret to manage.
 */
function deriveKey(purpose: "enc" | "hmac"): Buffer {
  const master = resolveMasterKey();
  return Buffer.from(
    crypto.hkdfSync("sha256", master, Buffer.alloc(0), purpose, KEY_BYTE_LEN)
  );
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Encrypt a plaintext string with AES-256-GCM.
 *
 * Returns a base64 string: iv(12) + authTag(16) + ciphertext.
 * When field encryption is disabled, returns the original value unchanged.
 */
export function encrypt(plaintext: string): string {
  if (!AUTH_FRAMEWORK_CONFIG.security.fieldEncryption) return plaintext;

  const key        = deriveKey("enc");
  const iv         = crypto.randomBytes(IV_LENGTH);
  const cipher     = crypto.createCipheriv(ALGORITHM, key, iv, {
    authTagLength: AUTH_TAG_LEN,
  });

  const encrypted  = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  const tag        = cipher.getAuthTag();

  return Buffer.concat([iv, tag, encrypted]).toString("base64");
}

/**
 * Decrypt a base64 blob produced by `encrypt()`.
 *
 * Throws if the authentication tag doesn't match (data tampered).
 * When field encryption is disabled, returns the original value unchanged.
 */
export function decrypt(ciphertext: string): string {
  if (!AUTH_FRAMEWORK_CONFIG.security.fieldEncryption) return ciphertext;

  const key     = deriveKey("enc");
  const buf     = Buffer.from(ciphertext, "base64");

  const iv      = buf.subarray(IV_START, TAG_START);
  const tag     = buf.subarray(TAG_START, CT_START);
  const payload = buf.subarray(CT_START);

  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv, {
    authTagLength: AUTH_TAG_LEN,
  });
  decipher.setAuthTag(tag);

  return (
    decipher.update(payload, undefined, "utf8") +
    decipher.final("utf8")
  );
}

/**
 * Produce a deterministic HMAC-SHA256 token for a searchable encrypted field.
 *
 * Use this as a separate indexed column (e.g. `emailHash`) so you can do:
 *   WHERE emailHash = hashForSearch(inputEmail)
 * without decrypting every row.
 *
 * When field encryption is disabled, returns the original value (lowercased for
 * email consistency) so existing WHERE queries keep working unchanged.
 */
export function hashForSearch(value: string): string {
  if (!AUTH_FRAMEWORK_CONFIG.security.fieldEncryption) {
    return value.toLowerCase();
  }

  const key = deriveKey("hmac");
  return crypto
    .createHmac("sha256", key)
    .update(value.toLowerCase())
    .digest("base64");
}
