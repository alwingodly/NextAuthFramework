"use server";

import bcrypt from "bcryptjs";
import { db } from "@/lib/db";
import { AUTH_FRAMEWORK_CONFIG } from "@/lib/auth/framework-config";
import { hashToken } from "@/lib/auth/token";
import { validatePasswordStrength } from "@/lib/auth/validation";
import {
  VALIDATION,
  RESET_PASSWORD_ERRORS,
} from "@/lib/messages";
import { type ActionResult, ok, fail } from "@/lib/result";

/**
 * resetPassword — validates a reset token and updates the user's password.
 *
 * SECURITY:
 *   - Token is hashed before DB lookup (raw token never stored).
 *   - Token is marked `used=true` immediately to prevent replay attacks.
 *   - Expired and used tokens are both rejected.
 *   - New password is bcrypt-hashed before storing.
 *   - On success, increment sessionVersion to invalidate all active sessions.
 */
export async function resetPassword(
  formData: FormData
): Promise<ActionResult<void>> {
  const rawToken       = formData.get("token");
  const password       = formData.get("password");
  const confirmPassword = formData.get("confirmPassword");

  // ── 1. Validate inputs ────────────────────────────────────────────────────
  if (
    typeof rawToken        !== "string" || !rawToken.trim() ||
    typeof password        !== "string" ||
    typeof confirmPassword !== "string"
  ) {
    return fail(RESET_PASSWORD_ERRORS.INVALID_TOKEN);
  }

  if (!password) return fail(RESET_PASSWORD_ERRORS.PASSWORD_REQUIRED);

  if (password.length < VALIDATION.PASSWORD_MIN_LENGTH) {
    return fail(RESET_PASSWORD_ERRORS.PASSWORD_TOO_SHORT);
  }

  if (password.length > VALIDATION.PASSWORD_MAX_LENGTH) {
    return fail(RESET_PASSWORD_ERRORS.PASSWORD_TOO_LONG);
  }

  const strengthResult = validatePasswordStrength(
    password,
    AUTH_FRAMEWORK_CONFIG.security.passwordRequireComplexity
  );
  if (!strengthResult.valid) {
    return fail(RESET_PASSWORD_ERRORS.PASSWORD_TOO_WEAK);
  }

  if (password !== confirmPassword) {
    return fail(RESET_PASSWORD_ERRORS.PASSWORDS_MISMATCH);
  }

  // ── 2. Look up the token (stored as hash) ─────────────────────────────────
  const tokenHash = hashToken(rawToken.trim());

  const record = await db.passwordResetToken.findUnique({
    where: { token: tokenHash },
  });

  if (!record)                        return fail(RESET_PASSWORD_ERRORS.INVALID_TOKEN);
  if (record.expiresAt < new Date())  return fail(RESET_PASSWORD_ERRORS.INVALID_TOKEN);

  // ── 3. Atomically claim the token ─────────────────────────────────────────
  // updateMany with `used: false` in the WHERE clause is a conditional atomic
  // write. Only one concurrent request can flip used false→true; any parallel
  // request gets count === 0 and is rejected as TOKEN_USED.
  const { count } = await db.passwordResetToken.updateMany({
    where: { token: tokenHash, used: false },
    data:  { used: true },
  });
  if (count === 0) return fail(RESET_PASSWORD_ERRORS.TOKEN_USED);

  // ── 4. Hash and save the new password, bump sessionVersion ────────────────
  const hashedPassword = await bcrypt.hash(
    password,
    AUTH_FRAMEWORK_CONFIG.security.bcryptCost
  );

  try {
    await db.user.update({
      where: { email: record.email },
      data: {
        password: hashedPassword,
        // Increment sessionVersion so all existing JWTs are treated as stale.
        // Other active sessions will expire within AUTH_SESSION_MAX_AGE_SECONDS.
        sessionVersion: { increment: 1 },
      },
    });
  } catch {
    return fail(RESET_PASSWORD_ERRORS.UPDATE_FAILED);
  }

  return ok();
}
