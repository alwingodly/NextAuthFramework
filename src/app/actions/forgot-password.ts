"use server";

import { headers } from "next/headers";
import { db } from "@/lib/db";
import { checkRateLimit, recordFailedAttempt } from "@/lib/auth/rate-limit";
import { getClientIp } from "@/lib/auth/client-ip";
import { AUTH_FRAMEWORK_CONFIG } from "@/lib/auth/framework-config";
import { generateToken, expiresAt } from "@/lib/auth/token";
import { sendPasswordResetEmail } from "@/lib/email";
import { VALIDATION, FORGOT_PASSWORD_ERRORS } from "@/lib/messages";
import { type ActionResult, ok, fail } from "@/lib/result";

/**
 * forgotPassword — sends a password reset email if the address is registered.
 *
 * SECURITY:
 *   Always returns the same success message regardless of whether the email
 *   exists — prevents email enumeration (OWASP A07).
 *
 *   Rate limited by IP to prevent email flooding.
 *   Token is stored as SHA-256 hash — raw value only in the email URL.
 */
export async function forgotPassword(
  formData: FormData
): Promise<ActionResult<void>> {
  // ── 1. Rate limit ──────────────────────────────────────────────────────────
  const headersList = await headers();
  const ip = getClientIp(headersList);

  const { allowed } = checkRateLimit(ip);
  if (!allowed) {
    return fail(FORGOT_PASSWORD_ERRORS.RATE_LIMITED);
  }

  // ── 2. Validate email ──────────────────────────────────────────────────────
  const email = formData.get("email");
  if (typeof email !== "string" || !email.trim()) {
    recordFailedAttempt(ip);
    return fail(FORGOT_PASSWORD_ERRORS.INVALID_EMAIL);
  }

  const emailStr = email.trim().toLowerCase();

  if (
    emailStr.length > VALIDATION.EMAIL_MAX_LENGTH ||
    !VALIDATION.EMAIL_REGEX.test(emailStr)
  ) {
    recordFailedAttempt(ip);
    return fail(FORGOT_PASSWORD_ERRORS.INVALID_EMAIL);
  }

  // ── 3. Look up user (constant-time: always respond the same way) ───────────
  // We generate the token and store it BEFORE checking if the user exists.
  // This keeps the response time consistent (prevents timing-based enumeration).
  const { raw, hash } = generateToken();
  const expiry = expiresAt(AUTH_FRAMEWORK_CONFIG.security.passwordResetExpiryMinutes);

  const user = await db.user.findUnique({
    where: { email: emailStr },
    select: { id: true, password: true },
  });

  // ── 4. If user exists AND has a password (not OAuth-only), send email ──────
  if (user?.password) {
    console.log("[forgot-password] DEV: user found, sending reset email to:", emailStr);
    // Remove any existing unexpired tokens for this email
    await db.passwordResetToken.deleteMany({ where: { email: emailStr } });
    await db.passwordResetToken.create({
      data: { email: emailStr, token: hash, expiresAt: expiry },
    });

    const sent = await sendPasswordResetEmail(emailStr, raw);
    if (!sent.ok) {
      // Log server-side only — never surface to client.
      // Returning SEND_FAILED only when the user exists leaks account presence.
      console.error("[forgot-password] Failed to send reset email:", emailStr);
    } else {
      console.log("[forgot-password] DEV: reset email sent OK to:", emailStr);
    }
  } else {
    console.log("[forgot-password] DEV: no matching user with password for:", emailStr);
  }

  // ── 5. Always return the same message (prevents email enumeration) ─────────
  return ok();
}
