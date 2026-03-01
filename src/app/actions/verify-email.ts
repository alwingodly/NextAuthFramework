"use server";

import { db } from "@/lib/db";
import { hashToken } from "@/lib/auth/token";
import { VERIFY_EMAIL_ERRORS } from "@/lib/messages";
import { type ActionResult, ok, fail } from "@/lib/result";

/**
 * verifyEmail — validates an email verification token and marks the user verified.
 *
 * SECURITY:
 *   - Token is hashed before DB lookup (raw token never stored).
 *   - Token record is deleted after successful verification (single-use).
 *   - Expired tokens are rejected.
 */
export async function verifyEmail(rawToken: string): Promise<ActionResult<void>> {
  if (!rawToken?.trim()) {
    return fail(VERIFY_EMAIL_ERRORS.INVALID_TOKEN);
  }

  const tokenHash = hashToken(rawToken.trim());

  // ── Look up the token ──────────────────────────────────────────────────────
  const record = await db.emailVerificationToken.findUnique({
    where: { token: tokenHash },
  });

  if (!record || record.expiresAt < new Date()) {
    return fail(VERIFY_EMAIL_ERRORS.INVALID_TOKEN);
  }

  // ── Mark user as verified and delete the token (atomic via transaction) ────
  await db.$transaction([
    db.user.update({
      where: { email: record.email },
      data:  { emailVerified: new Date() },
    }),
    db.emailVerificationToken.delete({
      where: { token: tokenHash },
    }),
  ]);

  return ok();
}
