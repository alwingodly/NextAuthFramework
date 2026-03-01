import "server-only";
import crypto from "crypto";

/**
 * token.ts — Secure random token helpers for password reset and email verification.
 *
 * PATTERN:
 *   1. Generate a cryptographically random raw token (sent in email URL).
 *   2. Store ONLY the SHA-256 hash in the database.
 *   3. On verification: hash the incoming URL token and compare with DB.
 *
 * WHY SHA-256 (not bcrypt)?
 *   - Tokens are 32 random bytes (256 bits of entropy) — brute-force is impossible.
 *   - SHA-256 is fast, which is fine here because the token itself has high entropy.
 *   - bcrypt's slowness is needed for passwords (low entropy); it's unnecessary here.
 *
 * SECURITY:
 *   - Tokens are single-use (marked `used=true` after verification).
 *   - Tokens expire after a configurable window (15 min for reset, 60 min for verify).
 *   - Even if the DB is leaked, the hashed tokens cannot be reversed.
 */

/** Generates a URL-safe raw token and its SHA-256 hash. */
export function generateToken(): { raw: string; hash: string } {
  const raw  = crypto.randomBytes(32).toString("hex"); // 64-char hex string
  const hash = hashToken(raw);
  return { raw, hash };
}

/** SHA-256 hash of a raw token string. Used to verify incoming URL tokens. */
export function hashToken(raw: string): string {
  return crypto.createHash("sha256").update(raw).digest("hex");
}

/** Returns a Date that is `minutes` from now. */
export function expiresAt(minutes: number): Date {
  return new Date(Date.now() + minutes * 60 * 1000);
}
