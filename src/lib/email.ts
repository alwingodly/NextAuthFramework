import "server-only";

/**
 * email.ts — Transactional email via Resend REST API
 *
 * Uses fetch directly — no SDK package required.
 * Get a free API key at https://resend.com (100 emails/day free tier).
 *
 * Required env vars:
 *   RESEND_API_KEY   — starts with "re_"
 *   AUTH_EMAIL_FROM  — e.g. "noreply@yourdomain.com" (must be verified in Resend)
 *   NEXT_PUBLIC_APP_URL — e.g. "https://yourapp.com" (no trailing slash)
 */

// ─── Types ────────────────────────────────────────────────────────────────────

interface SendEmailOptions {
  to: string;
  subject: string;
  html: string;
}

interface SendEmailResult {
  ok: boolean;
  error?: string;
}

// ─── Core sender ──────────────────────────────────────────────────────────────

export async function sendEmail(opts: SendEmailOptions): Promise<SendEmailResult> {
  const apiKey = process.env.RESEND_API_KEY;
  const from   = process.env.AUTH_EMAIL_FROM;

  if (!apiKey || !from) {
    console.error("[email] RESEND_API_KEY or AUTH_EMAIL_FROM is not set.");
    return { ok: false, error: "Email not configured" };
  }

  try {
    const res = await fetch("https://api.resend.com/emails", {
      method:  "POST",
      headers: {
        "Authorization": `Bearer ${apiKey}`,
        "Content-Type":  "application/json",
      },
      body: JSON.stringify({ from, to: opts.to, subject: opts.subject, html: opts.html }),
    });

    if (!res.ok) {
      const body = await res.text();
      console.error(`[email] Resend API error ${res.status}: ${body}`);
      return { ok: false, error: "Failed to send email" };
    }

    return { ok: true };
  } catch (err) {
    console.error("[email] Network error sending email:", err);
    return { ok: false, error: "Failed to send email" };
  }
}

// ─── App URL helper ───────────────────────────────────────────────────────────

function appUrl(path: string): string {
  const base = process.env.NEXT_PUBLIC_APP_URL ?? "http://localhost:3000";
  return `${base.replace(/\/$/, "")}${path}`;
}

// ─── Email Templates ──────────────────────────────────────────────────────────

/**
 * Sends a password reset link to the user's email.
 * The raw token is embedded in the URL — only the SHA-256 hash is stored in DB.
 */
export async function sendPasswordResetEmail(
  email: string,
  rawToken: string
): Promise<SendEmailResult> {
  const link = appUrl(`/reset-password?token=${rawToken}`);

  return sendEmail({
    to:      email,
    subject: "Reset your password",
    html: `
      <div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:32px">
        <h2 style="margin:0 0 16px">Reset your password</h2>
        <p style="color:#555;margin:0 0 24px">
          Click the button below to set a new password.
          This link expires in 15 minutes.
        </p>
        <a href="${link}"
           style="display:inline-block;background:#18181b;color:#fff;padding:12px 24px;
                  border-radius:8px;text-decoration:none;font-weight:600">
          Reset password
        </a>
        <p style="color:#888;font-size:13px;margin:24px 0 0">
          If you didn&apos;t request a password reset, ignore this email.
        </p>
      </div>
    `,
  });
}

/**
 * Sends an email verification link to a newly registered user.
 * The raw token is embedded in the URL — only the SHA-256 hash is stored in DB.
 */
export async function sendEmailVerificationEmail(
  email: string,
  rawToken: string
): Promise<SendEmailResult> {
  const link = appUrl(`/verify-email?token=${rawToken}`);

  return sendEmail({
    to:      email,
    subject: "Verify your email address",
    html: `
      <div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:32px">
        <h2 style="margin:0 0 16px">Verify your email</h2>
        <p style="color:#555;margin:0 0 24px">
          Click the button below to verify your email address and activate your account.
          This link expires in 60 minutes.
        </p>
        <a href="${link}"
           style="display:inline-block;background:#18181b;color:#fff;padding:12px 24px;
                  border-radius:8px;text-decoration:none;font-weight:600">
          Verify email
        </a>
        <p style="color:#888;font-size:13px;margin:24px 0 0">
          If you didn&apos;t create an account, ignore this email.
        </p>
      </div>
    `,
  });
}
