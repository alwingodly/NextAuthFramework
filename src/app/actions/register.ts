"use server";

/**
 * register.ts — Server Action for User Registration
 *
 * ─── WHAT THIS FILE DOES ────────────────────────────────────────────────────
 *
 *  Handles new user sign-up. Called from RegisterForm.tsx when the form is
 *  submitted. Returns a typed result object — never throws to the client.
 *
 * ─── FLOW ────────────────────────────────────────────────────────────────────
 *
 *  1. Rate limit by IP           → blocks registration spam / DoS
 *  2. Input validation           → name, email format, password strength,
 *                                   password confirmation match
 *  3. Hash password              → bcrypt cost=12 (~300ms per hash)
 *  4. Check for existing email   → avoids duplicate accounts (with timing
 *                                   attack mitigation — see note below)
 *  5. Create user in DB          → role defaults to USER (see schema)
 *  6. Return success             → RegisterForm redirects to /login
 *
 * ─── SECURITY NOTES ─────────────────────────────────────────────────────────
 *
 *  OWASP A07 — Broken Auth:
 *    - bcrypt cost=12 makes offline brute-force of leaked hashes very slow
 *    - Rate limiting prevents mass registrations from a single IP
 *
 *  OWASP A03 — Injection:
 *    - All DB writes use Prisma ORM (parameterised)
 *    - Input validated before any DB operation
 *
 *  EMAIL ENUMERATION:
 *    If we return "email already exists" as an error, an attacker can
 *    enumerate which emails are registered. We return the same generic
 *    message for duplicate emails as for other failures.
 *
 *  TIMING ATTACK MITIGATION:
 *    We hash BEFORE the duplicate-email check so response time is always
 *    ~300ms regardless of whether the email was already registered.
 */

import bcrypt from "bcryptjs";
import { headers } from "next/headers";
import { db } from "@/lib/db";
import { checkRateLimit, recordFailedAttempt } from "@/lib/auth/rate-limit";
import { getClientIp } from "@/lib/auth/client-ip";
import { AUTH_FRAMEWORK_CONFIG } from "@/lib/auth/framework-config";
import { validatePasswordStrength } from "@/lib/auth/validation";
import { generateToken, expiresAt } from "@/lib/auth/token";
import { sendEmailVerificationEmail } from "@/lib/email";
import { VALIDATION, REGISTER_ERRORS } from "@/lib/messages";
import { type ActionResult, ok, fail } from "@/lib/result";

export async function register(
  formData: FormData
): Promise<ActionResult<{ requiresVerification: boolean }>> {
  // ── 1. Rate limit by IP ────────────────────────────────────────────────────
  const headersList = await headers();
  const ip = getClientIp(headersList);

  const { allowed } = checkRateLimit(ip);
  if (!allowed) {
    return fail(REGISTER_ERRORS.RATE_LIMITED);
  }

  // ── 2. Extract and type-check inputs ──────────────────────────────────────
  const name            = formData.get("name");
  const email           = formData.get("email");
  const password        = formData.get("password");
  const confirmPassword = formData.get("confirmPassword");

  if (
    typeof email           !== "string" ||
    typeof password        !== "string" ||
    typeof confirmPassword !== "string"
  ) {
    recordFailedAttempt(ip);
    return fail(REGISTER_ERRORS.INVALID_INPUT);
  }

  const nameStr    = typeof name === "string" ? name.trim() : "";
  const emailStr   = email.trim().toLowerCase();
  const passwordStr = password;
  const confirmStr  = confirmPassword;

  // ── 3. Input validation ────────────────────────────────────────────────────

  if (!emailStr) {
    recordFailedAttempt(ip);
    return fail(REGISTER_ERRORS.EMAIL_REQUIRED);
  }

  if (emailStr.length > VALIDATION.EMAIL_MAX_LENGTH || !VALIDATION.EMAIL_REGEX.test(emailStr)) {
    recordFailedAttempt(ip);
    return fail(REGISTER_ERRORS.EMAIL_INVALID);
  }

  if (nameStr.length > VALIDATION.NAME_MAX_LENGTH) {
    recordFailedAttempt(ip);
    return fail(REGISTER_ERRORS.NAME_TOO_LONG);
  }

  if (!passwordStr) {
    recordFailedAttempt(ip);
    return fail(REGISTER_ERRORS.PASSWORD_REQUIRED);
  }

  if (passwordStr.length < VALIDATION.PASSWORD_MIN_LENGTH) {
    recordFailedAttempt(ip);
    return fail(REGISTER_ERRORS.PASSWORD_TOO_SHORT);
  }

  if (passwordStr.length > VALIDATION.PASSWORD_MAX_LENGTH) {
    recordFailedAttempt(ip);
    return fail(REGISTER_ERRORS.PASSWORD_TOO_LONG);
  }

  // ── 3b. Password complexity (when AUTH_PASSWORD_REQUIRE_COMPLEXITY=true) ───
  const strengthResult = validatePasswordStrength(
    passwordStr,
    AUTH_FRAMEWORK_CONFIG.security.passwordRequireComplexity
  );
  if (!strengthResult.valid) {
    recordFailedAttempt(ip);
    return fail(REGISTER_ERRORS.PASSWORD_TOO_WEAK);
  }

  if (passwordStr !== confirmStr) {
    recordFailedAttempt(ip);
    return fail(REGISTER_ERRORS.PASSWORDS_MISMATCH);
  }

  // ── 4. Hash BEFORE duplicate check (timing attack mitigation) ─────────────
  const hashedPassword = await bcrypt.hash(
    passwordStr,
    AUTH_FRAMEWORK_CONFIG.security.bcryptCost
  );

  // ── 5. Check for existing email ────────────────────────────────────────────
  const existingUser = await db.user.findUnique({
    where: { email: emailStr },
    select: { id: true },
  });

  if (existingUser) {
    recordFailedAttempt(ip);
    return fail(REGISTER_ERRORS.ACCOUNT_CREATION_FAILED);
  }

  // ── 6. Create the user ─────────────────────────────────────────────────────
  try {
    await db.user.create({
      data: {
        name: nameStr || null,
        email: emailStr,
        password: hashedPassword,
      },
    });
  } catch {
    return fail(REGISTER_ERRORS.ACCOUNT_CREATION_FAILED);
  }

  // ── 7. Send verification email (when AUTH_REQUIRE_EMAIL_VERIFICATION=true) ─
  if (AUTH_FRAMEWORK_CONFIG.security.requireEmailVerification) {
    const { raw, hash } = generateToken();
    const expiry = expiresAt(AUTH_FRAMEWORK_CONFIG.security.emailVerificationExpiryMinutes);

    // Delete any previous unused token for this email before creating a new one
    await db.emailVerificationToken.deleteMany({ where: { email: emailStr } });
    await db.emailVerificationToken.create({
      data: { email: emailStr, token: hash, expiresAt: expiry },
    });

    await sendEmailVerificationEmail(emailStr, raw);
    // Return success=true but signal that verification is pending
    return ok({ requiresVerification: true });
  }

  return ok({ requiresVerification: false });
}
