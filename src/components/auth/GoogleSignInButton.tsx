/**
 * GoogleSignInButton.tsx — Google OAuth Sign-In Button (Client Component)
 *
 * ─── FLOW ON CLICK ───────────────────────────────────────────────────────────
 *
 *  1. User clicks → signIn("google", { callbackUrl: "/user" })
 *  2. Browser redirects to accounts.google.com consent screen
 *  3. User consents → Google redirects back to /api/auth/callback/google
 *  4. NextAuth exchanges the code for the user's profile (name, email, picture)
 *  5. NextAuth upserts User + Account rows in the database (via PrismaAdapter)
 *  6. jwt() callback checks if email is in ADMIN_EMAILS → assigns role
 *  7. JWT cookie is set → browser is redirected to callbackUrl (/user)
 *  8. proxy.ts/the page re-reads the session from the cookie
 *
 * ─── SECURITY ────────────────────────────────────────────────────────────────
 *
 *  OAuth state parameter (CSRF protection): NextAuth generates a random `state`
 *  value before the redirect and verifies it on the callback. This prevents
 *  an attacker from tricking a user into completing an OAuth flow they didn't
 *  initiate (OWASP A01 — CSRF on OAuth).
 *
 *  PKCE is enabled in NextAuth v5 by default, adding a second layer of
 *  protection for the code exchange step.
 *
 *  We never see the user's Google password — Google handles authentication.
 */
"use client";

import { useState } from "react";
import { signIn } from "next-auth/react";
import { useRouter } from "next/navigation";
import { AUTH_ROUTES } from "@/lib/auth/routes";
import { AUTH_ERRORS, UI } from "@/lib/messages";

export function GoogleSignInButton() {
  const router = useRouter();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function handleGoogleSignIn() {
    try {
      setError("");
      setLoading(true);
      const result = await signIn("google", {
        redirect: false,
        callbackUrl: AUTH_ROUTES.userHome,
      });

      if (result?.error) {
        setError(AUTH_ERRORS.GOOGLE_FAILED);
        setLoading(false);
        return;
      }

      if (result?.url) {
        router.push(result.url);
        return;
      }

      setError(AUTH_ERRORS.GOOGLE_FAILED);
      setLoading(false);
    } catch {
      setError(AUTH_ERRORS.GOOGLE_FAILED);
      setLoading(false);
    }
  }

  return (
    <div className="flex flex-col gap-2">
      <button
        type="button"
        onClick={handleGoogleSignIn}
        disabled={loading}
        className="flex w-full items-center justify-center gap-3 rounded-lg border border-zinc-300 bg-white px-4 py-2.5 text-sm font-medium text-zinc-700 transition hover:bg-zinc-50 disabled:cursor-not-allowed disabled:opacity-60 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-300 dark:hover:bg-zinc-800"
      >
        <svg className="h-5 w-5" viewBox="0 0 24 24" aria-hidden="true">
          <path
            d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
            fill="#4285F4"
          />
          <path
            d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
            fill="#34A853"
          />
          <path
            d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
            fill="#FBBC05"
          />
          <path
            d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
            fill="#EA4335"
          />
        </svg>
        {loading ? UI.REDIRECTING : UI.CONTINUE_WITH_GOOGLE}
      </button>

      {error && (
        <p className="rounded-lg bg-red-50 px-3 py-2 text-sm text-red-600 dark:bg-red-950 dark:text-red-400">
          {error}
        </p>
      )}
    </div>
  );
}
