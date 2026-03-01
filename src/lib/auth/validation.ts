/**
 * validation.ts — Server-side input validation for auth credentials
 *
 * OWASP: A03 Injection, A07 Identification and Authentication Failures
 *
 * WHY SERVER-SIDE VALIDATION?
 *   The browser's `type="email"` and `required` attributes can be bypassed
 *   by anyone using curl, Postman, or browser dev tools. Server-side
 *   validation is the REAL security boundary — client-side is just UX.
 *
 * WHAT WE VALIDATE:
 *   1. Email — must be a real email format (not just a non-empty string).
 *   2. Password — must meet minimum length (prevents empty string attacks).
 *   3. Input length — we cap maximum lengths to prevent DoS via huge payloads
 *      (e.g. bcrypt has a 72-byte input limit; passing 100KB crashes nothing
 *      but wastes CPU and memory).
 *
 * WHAT WE DELIBERATELY DO NOT VALIDATE:
 *   - Whether the email EXISTS in the database (that check is in config.ts).
 *     We don't want to hint to attackers that "this email is not registered".
 *   - Password complexity rules (uppercase, special chars etc.) — those belong
 *     in a registration flow, not a login validation.
 *
 * SECURITY DESIGN:
 *   - All error messages are generic. We never say "email format is wrong"
 *     because that gives attackers information about what specifically failed.
 *   - The function returns a single boolean + single message rather than
 *     field-level errors, making it harder to probe the validation logic.
 */

import { VALIDATION, LOGIN_VALIDATION_ERRORS } from "@/lib/messages";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface ValidationResult {
  valid: boolean;
  /** Human-readable error message. Generic by design — see note above. */
  error?: string;
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * validateLoginCredentials — validates email and password before any DB lookup.
 *
 * Call this at the START of the `authorize()` callback, before touching the DB.
 * Failing fast on invalid input saves a DB round-trip and prevents some attacks.
 *
 * @example
 * const { valid, error } = validateLoginCredentials(email, password);
 * if (!valid) return null; // never leak the `error` string to the client
 */
export function validateLoginCredentials(
  email: unknown,
  password: unknown
): ValidationResult {
  // ── Type guards ────────────────────────────────────────────────────────────
  // Inputs arrive as `unknown` from the NextAuth credentials object.
  // An attacker can send any type via a raw API request.
  if (typeof email !== "string" || typeof password !== "string") {
    return { valid: false, error: LOGIN_VALIDATION_ERRORS.INVALID_TYPE };
  }

  // ── Emptiness check ────────────────────────────────────────────────────────
  if (!email.trim() || !password.trim()) {
    return { valid: false, error: LOGIN_VALIDATION_ERRORS.REQUIRED };
  }

  // ── Length limits ─────────────────────────────────────────────────────────
  // Long inputs can be used in DoS attacks or to exploit parsing vulnerabilities.
  if (email.length > VALIDATION.EMAIL_MAX_LENGTH) {
    return { valid: false, error: LOGIN_VALIDATION_ERRORS.INVALID };
  }

  if (password.length > VALIDATION.PASSWORD_MAX_LENGTH) {
    return { valid: false, error: LOGIN_VALIDATION_ERRORS.INVALID };
  }

  if (password.length < VALIDATION.PASSWORD_MIN_LENGTH) {
    return { valid: false, error: LOGIN_VALIDATION_ERRORS.INVALID };
  }

  // ── Email format ───────────────────────────────────────────────────────────
  if (!VALIDATION.EMAIL_REGEX.test(email)) {
    return { valid: false, error: LOGIN_VALIDATION_ERRORS.INVALID };
  }

  return { valid: true };
}

/**
 * validatePasswordStrength — checks complexity requirements during REGISTRATION.
 *
 * Only called at registration, not login. When AUTH_PASSWORD_REQUIRE_COMPLEXITY=true,
 * password must have at least one uppercase, one lowercase, and one digit.
 *
 * @param requireComplexity  Value from AUTH_FRAMEWORK_CONFIG.security.passwordRequireComplexity
 */
export function validatePasswordStrength(
  password: string,
  requireComplexity: boolean
): ValidationResult {
  if (!requireComplexity) return { valid: true };

  if (!VALIDATION.PASSWORD_COMPLEXITY_REGEX.test(password)) {
    return {
      valid: false,
      error: "Password must contain uppercase, lowercase, and a number.",
    };
  }

  return { valid: true };
}
