import "server-only";

/**
 * Shared auth framework configuration.
 *
 * Keep reusable knobs here so this auth layer can be moved between projects
 * with minimal edits.
 */

export interface AuthFrameworkConfig {
  providers: {
    google: boolean;
    credentials: boolean;
  };
  security: {
    bcryptCost: number;
    trustHost: boolean;
    trustProxyHeaders: boolean;
    rateLimit: {
      maxAttempts: number;
      windowMs: number;
    };
    /** When true, AES-256-GCM encrypts sensitive DB fields. Requires ENCRYPTION_KEY. */
    fieldEncryption: boolean;
    /** When true, encrypts API request/response bodies. Requires PAYLOAD_ENCRYPTION_KEY. */
    requestEncryption: boolean;
    /**
     * When true, credential registrations must verify email before logging in.
     * Google OAuth users are always verified automatically.
     * Requires RESEND_API_KEY + AUTH_EMAIL_FROM env vars.
     */
    requireEmailVerification: boolean;
    /** How long (minutes) an email verification link is valid. Default: 60. */
    emailVerificationExpiryMinutes: number;
    /** How long (minutes) a password reset link is valid. Default: 15. */
    passwordResetExpiryMinutes: number;
    /**
     * When true, registration requires password complexity:
     * at least one uppercase, one lowercase, and one digit.
     * Minimum length is always enforced regardless.
     */
    passwordRequireComplexity: boolean;
    /**
     * JWT session lifetime in seconds. Default: 30 days (2592000).
     * Shorten this (e.g. 3600 = 1 hour) when using "sign out all devices"
     * so that revoked sessions on other devices expire sooner.
     */
    sessionMaxAgeSeconds: number;
  };
}

function parseBoolean(value: string | undefined, defaultValue: boolean): boolean {
  if (value === undefined) return defaultValue;
  return value === "true";
}

function parsePositiveInt(value: string | undefined, defaultValue: number): number {
  if (!value) return defaultValue;
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : defaultValue;
}

// ─── Production safety checks ─────────────────────────────────────────────────
if (process.env.NODE_ENV === "production") {
  if (process.env.AUTH_TRUST_HOST === "true") {
    console.error(
      "[auth] DANGER: AUTH_TRUST_HOST=true in production disables Auth.js host " +
      "header validation. Only set this if you fully control the reverse proxy " +
      "and understand the CSRF implications. Remove it if unsure."
    );
  }
  if (
    process.env.AUTH_REQUEST_ENCRYPTION === "true" &&
    process.env.AUTH_FIELD_ENCRYPTION === "true" &&
    process.env.ENCRYPTION_KEY === process.env.PAYLOAD_ENCRYPTION_KEY
  ) {
    console.error(
      "[auth] DANGER: ENCRYPTION_KEY and PAYLOAD_ENCRYPTION_KEY are identical. " +
      "They must be different keys. PAYLOAD_ENCRYPTION_KEY is sent to browsers; " +
      "using the same key exposes your DB field encryption key to clients."
    );
  }
  if (
    process.env.AUTH_REQUIRE_EMAIL_VERIFICATION === "true" &&
    !process.env.RESEND_API_KEY?.startsWith("re_")
  ) {
    console.error(
      "[auth] DANGER: AUTH_REQUIRE_EMAIL_VERIFICATION=true but RESEND_API_KEY is " +
      "missing or invalid. Users will not receive verification emails. " +
      "Get a key at https://resend.com"
    );
  }
}

export const AUTH_FRAMEWORK_CONFIG: AuthFrameworkConfig = {
  providers: {
    google: parseBoolean(process.env.AUTH_ENABLE_GOOGLE, true),
    credentials: parseBoolean(process.env.AUTH_ENABLE_CREDENTIALS, true),
  },
  security: {
    bcryptCost: parsePositiveInt(process.env.AUTH_BCRYPT_COST, 12),
    trustHost: parseBoolean(
      process.env.AUTH_TRUST_HOST,
      process.env.NODE_ENV !== "production"
    ),
    trustProxyHeaders: parseBoolean(process.env.AUTH_TRUST_PROXY_HEADERS, false),
    fieldEncryption: parseBoolean(process.env.AUTH_FIELD_ENCRYPTION, false),
    requestEncryption: parseBoolean(process.env.AUTH_REQUEST_ENCRYPTION, false),
    requireEmailVerification: parseBoolean(process.env.AUTH_REQUIRE_EMAIL_VERIFICATION, false),
    emailVerificationExpiryMinutes: parsePositiveInt(
      process.env.AUTH_EMAIL_VERIFICATION_EXPIRY_MINUTES,
      60
    ),
    passwordResetExpiryMinutes: parsePositiveInt(
      process.env.AUTH_PASSWORD_RESET_EXPIRY_MINUTES,
      15
    ),
    passwordRequireComplexity: parseBoolean(process.env.AUTH_PASSWORD_REQUIRE_COMPLEXITY, false),
    sessionMaxAgeSeconds: parsePositiveInt(
      process.env.AUTH_SESSION_MAX_AGE_SECONDS,
      30 * 24 * 60 * 60 // 30 days
    ),
    rateLimit: {
      maxAttempts: parsePositiveInt(process.env.AUTH_RATE_LIMIT_MAX_ATTEMPTS, 5),
      windowMs: parsePositiveInt(
        process.env.AUTH_RATE_LIMIT_WINDOW_MS,
        15 * 60 * 1000
      ),
    },
  },
};

/**
 * Comma-separated list in env, e.g.:
 * AUTH_ADMIN_EMAILS="admin@acme.com,security@acme.com"
 */
export const ADMIN_EMAILS: string[] = (process.env.AUTH_ADMIN_EMAILS ?? "")
  .split(",")
  .map((value) => value.trim().toLowerCase())
  .filter(Boolean);

/**
 * Emails that are automatically promoted to STAFF on first OAuth login.
 * Comma-separated list in env, e.g.:
 * AUTH_STAFF_EMAILS="doctor@clinic.com,nurse@clinic.com"
 *
 * Note: ADMIN_EMAILS takes precedence — if an email is in both lists,
 * the user gets ADMIN role.
 */
export const STAFF_EMAILS: string[] = (process.env.AUTH_STAFF_EMAILS ?? "")
  .split(",")
  .map((value) => value.trim().toLowerCase())
  .filter(Boolean);
