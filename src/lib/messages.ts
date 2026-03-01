/**
 * messages.ts — Centralized application message constants
 *
 * ENTERPRISE PATTERN:
 *   All user-facing strings live here. Never inline strings in components or
 *   actions. Benefits:
 *     - Single place to change copy, translate, or A/B test messages
 *     - TypeScript `as const` ensures strings are literal types (no typos)
 *     - Security: generic auth messages are co-located with a comment explaining WHY
 *
 * USAGE:
 *   import { AUTH_ERRORS, REGISTER_ERRORS, UI, VALIDATION } from "@/lib/messages";
 */

// ─── Validation Constraints ───────────────────────────────────────────────────
// Single source of truth for all input limits. Used by both server actions
// and validation.ts so limits never drift out of sync.

export const VALIDATION = {
  PASSWORD_MIN_LENGTH: 8,
  PASSWORD_MAX_LENGTH: 72, // bcrypt silently truncates beyond 72 bytes
  NAME_MAX_LENGTH: 100,
  EMAIL_MAX_LENGTH: 254,   // RFC 5321 maximum
  EMAIL_REGEX: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
  // Complexity: at least one uppercase, one lowercase, one digit.
  // Only enforced when AUTH_PASSWORD_REQUIRE_COMPLEXITY=true.
  PASSWORD_COMPLEXITY_REGEX: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).+$/,
} as const;

// ─── Auth Error Messages (Generic by design) ──────────────────────────────────
// SECURITY: These messages are intentionally vague to prevent:
//   - Username/email enumeration (OWASP A07)
//   - Timing-based probing (don't say "rate limited" vs "wrong password")
//   Never add specific failure reasons to these constants.

export const AUTH_ERRORS = {
  INVALID_CREDENTIALS: "Invalid email or password.",
  RATE_LIMITED:        "Unable to process request. Please try again later.",
  GOOGLE_FAILED:       "Google sign-in failed. Please try again.",
  EMAIL_NOT_VERIFIED:  "Please verify your email address before signing in.",
} as const;

// ─── Registration Error Messages ─────────────────────────────────────────────
// Registration CAN expose specific validation errors (email format, password
// rules) since those help the user fill the form correctly and do not reveal
// whether a specific email is already registered.

export const REGISTER_ERRORS = {
  RATE_LIMITED:            "Unable to create account. Please try again later.",
  INVALID_INPUT:           "Invalid form submission.",
  EMAIL_REQUIRED:          "Email is required.",
  EMAIL_INVALID:           "Please enter a valid email address.",
  NAME_TOO_LONG:           "Name is too long.",
  PASSWORD_REQUIRED:       "Password is required.",
  PASSWORD_TOO_SHORT:      `Password must be at least ${VALIDATION.PASSWORD_MIN_LENGTH} characters.`,
  PASSWORD_TOO_LONG:       "Password is too long.",
  PASSWORD_TOO_WEAK:       "Password must contain uppercase, lowercase, and a number.",
  PASSWORDS_MISMATCH:      "Passwords do not match.",
  ACCOUNT_CREATION_FAILED: "Unable to create account. Please try again.",
} as const;

// ─── Login Validation Error Messages (Generic by design) ──────────────────────
// These are returned internally from validateLoginCredentials().
// They are logged server-side only — never shown directly to the user.
// The caller (authorize()) always returns null to the client.

export const LOGIN_VALIDATION_ERRORS = {
  INVALID_TYPE: "Invalid input types",
  REQUIRED:     "Email and password are required",
  INVALID:      "Invalid credentials",
} as const;

// ─── Forgot Password Messages ─────────────────────────────────────────────────
// Always generic — never reveal whether an email is registered.

export const FORGOT_PASSWORD_ERRORS = {
  RATE_LIMITED:  "Unable to process request. Please try again later.",
  INVALID_EMAIL: "Please enter a valid email address.",
  SEND_FAILED:   "Unable to send reset email. Please try again.",
} as const;

export const FORGOT_PASSWORD_SUCCESS =
  "If that email is registered, a reset link has been sent. Check your inbox.";

// ─── Reset Password Messages ──────────────────────────────────────────────────

export const RESET_PASSWORD_ERRORS = {
  INVALID_TOKEN:      "This reset link is invalid or has expired. Please request a new one.",
  TOKEN_USED:         "This reset link has already been used. Please request a new one.",
  PASSWORD_REQUIRED:  "New password is required.",
  PASSWORD_TOO_SHORT: `Password must be at least ${VALIDATION.PASSWORD_MIN_LENGTH} characters.`,
  PASSWORD_TOO_LONG:  "Password is too long.",
  PASSWORD_TOO_WEAK:  "Password must contain uppercase, lowercase, and a number.",
  PASSWORDS_MISMATCH: "Passwords do not match.",
  UPDATE_FAILED:      "Unable to update password. Please try again.",
} as const;

export const RESET_PASSWORD_SUCCESS =
  "Password updated. You can now sign in with your new password.";

// ─── Email Verification Messages ─────────────────────────────────────────────

export const VERIFY_EMAIL_ERRORS = {
  INVALID_TOKEN: "This verification link is invalid or has expired.",
  SEND_FAILED:   "Unable to send verification email. Please try again.",
} as const;

export const VERIFY_EMAIL_SUCCESS = "Email verified. You can now sign in.";

// ─── Login Page Feedback Messages ─────────────────────────────────────────────
// Shown as a green success banner on the login page when redirected from
// another auth flow. Keyed by the ?message= query param value.

export const LOGIN_MESSAGES = {
  "password-reset": "Password updated. You can now sign in with your new password.",
  "registered":     "Account created! Sign in to get started.",
} as const;

// ─── UI Labels & Copy ─────────────────────────────────────────────────────────

export const UI = {
  // Buttons
  SIGN_IN:               "Sign in",
  SIGN_OUT:              "Sign out",
  SIGN_OUT_ALL:          "Sign out all devices",
  CREATE_ACCOUNT:        "Create account",
  CONTINUE_WITH_GOOGLE:  "Continue with Google",
  SEND_RESET_LINK:       "Send reset link",
  RESET_PASSWORD:        "Reset password",

  // Loading states
  SIGNING_IN:            "Signing in\u2026",
  CREATING_ACCOUNT:      "Creating account\u2026",
  REDIRECTING:           "Redirecting\u2026",
  SENDING:               "Sending\u2026",
  RESETTING:             "Resetting\u2026",

  // Page headings
  LOGIN_HEADING:              "Welcome back",
  LOGIN_SUBHEADING:           "Sign in to your account",
  REGISTER_HEADING:           "Create an account",
  REGISTER_SUBHEADING:        "Sign up to get started",
  FORGOT_PASSWORD_HEADING:    "Forgot your password?",
  FORGOT_PASSWORD_SUBHEADING: "Enter your email and we\u2019ll send a reset link.",
  RESET_PASSWORD_HEADING:     "Set a new password",
  VERIFY_EMAIL_HEADING:       "Check your email",
  VERIFY_EMAIL_SUBHEADING:    "We sent a verification link to your email address.",
  ADMIN_PANEL:                "Admin Panel",
  DASHBOARD:                  "Dashboard",

  // Form labels
  LABEL_NAME:             "Name",
  LABEL_NAME_OPTIONAL:    "(optional)",
  LABEL_EMAIL:            "Email",
  LABEL_PASSWORD:         "Password",
  LABEL_NEW_PASSWORD:     "New password",
  LABEL_CONFIRM_PASSWORD: "Confirm Password",

  // Placeholders
  PLACEHOLDER_NAME:         "Jane Smith",
  PLACEHOLDER_EMAIL:        "you@example.com",
  PLACEHOLDER_PASSWORD:     "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022",
  PLACEHOLDER_NEW_PASSWORD: "Min. 8 characters",

  // Password hint (shown when AUTH_PASSWORD_REQUIRE_COMPLEXITY=true)
  PASSWORD_HINT: "Min. 8 characters \u00b7 uppercase \u00b7 lowercase \u00b7 number",

  // Links
  NO_ACCOUNT:      "Don\u2019t have an account?",
  HAS_ACCOUNT:     "Already have an account?",
  CREATE_ONE:      "Create one",
  FORGOT_PASSWORD: "Forgot password?",
  BACK_TO_LOGIN:   "Back to sign in",

  // Admin / User pages
  NO_USERS:      "No users yet.",
  ROLE_LABEL:    "Role:",
  UNKNOWN_USER:  "Unknown",
  FALLBACK_NAME: "\u2014",
} as const;
