/**
 * SignInForm.tsx — Email/Password Login Form (Client Component)
 *
 * ─── FLOW ON SUBMIT ─────────────────────────────────────────────────────────
 *
 *  1. User fills in email + password → clicks "Sign in"
 *  2. signIn("credentials", { redirect: false }) → POST /api/auth/callback/credentials
 *  3. Server runs authorize() in lib/auth/config.ts:
 *       rate limit → input validation → DB lookup → bcrypt.compare()
 *  4. Success → server sets HttpOnly JWT cookie → router.push(/user)
 *     Failure → res.error set → display "Invalid email or password"
 *
 * ─── WHY redirect: false ────────────────────────────────────────────────────
 *
 *  Keeps the user on the page so we can show an inline error message instead
 *  of navigating to NextAuth's error page. We handle the redirect manually.
 *
 * ─── SECURITY ────────────────────────────────────────────────────────────────
 *
 *  This component is just a UI — real security lives in authorize().
 *  Error messages are deliberately generic (OWASP A07 — no username enumeration).
 *  The loading/disabled state prevents double-submission (UX — real rate
 *  limiting is server-side in rate-limit.ts).
 */
"use client";

import { useState } from "react";
import { signIn } from "next-auth/react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { AUTH_ROUTES } from "@/lib/auth/routes";
import { AUTH_ERRORS, UI } from "@/lib/messages";

export function SignInForm() {
  const router = useRouter();
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: React.SyntheticEvent<HTMLFormElement>) {
    e.preventDefault();
    setError("");
    setLoading(true);

    const form = e.currentTarget;
    const email = (form.elements.namedItem("email") as HTMLInputElement).value;
    const password = (form.elements.namedItem("password") as HTMLInputElement).value;

    const res = await signIn("credentials", {
      email,
      password,
      redirect: false,
    });

    setLoading(false);

    if (res?.error) {
      setError(AUTH_ERRORS.INVALID_CREDENTIALS);
      return;
    }

    // Redirect handled by the page after session refresh
    router.push(AUTH_ROUTES.userHome);
    router.refresh();
  }

  return (
    <form onSubmit={handleSubmit} className="flex flex-col gap-4">
      <div className="flex flex-col gap-1">
        <label htmlFor="email" className="text-sm font-medium text-zinc-700 dark:text-zinc-300">
          Email
        </label>
        <input
          id="email"
          name="email"
          type="email"
          required
          placeholder="you@example.com"
          className="rounded-lg border border-zinc-300 bg-white px-4 py-2.5 text-sm text-zinc-900 placeholder-zinc-400 outline-none focus:border-zinc-900 focus:ring-2 focus:ring-zinc-900/10 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-100 dark:focus:border-zinc-400"
        />
      </div>

      <div className="flex flex-col gap-1">
        <div className="flex items-center justify-between">
          <label htmlFor="password" className="text-sm font-medium text-zinc-700 dark:text-zinc-300">
            Password
          </label>
          <Link
            href={AUTH_ROUTES.forgotPassword}
            className="text-xs text-zinc-500 underline-offset-4 hover:underline dark:text-zinc-400"
          >
            {UI.FORGOT_PASSWORD}
          </Link>
        </div>
        <input
          id="password"
          name="password"
          type="password"
          required
          placeholder="••••••••"
          className="rounded-lg border border-zinc-300 bg-white px-4 py-2.5 text-sm text-zinc-900 placeholder-zinc-400 outline-none focus:border-zinc-900 focus:ring-2 focus:ring-zinc-900/10 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-100 dark:focus:border-zinc-400"
        />
      </div>

      {error && (
        <p className="rounded-lg bg-red-50 px-4 py-2 text-sm text-red-600 dark:bg-red-950 dark:text-red-400">
          {error}
        </p>
      )}

      <button
        type="submit"
        disabled={loading}
        className="rounded-lg bg-zinc-900 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-zinc-700 disabled:opacity-50 dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-zinc-300"
      >
        {loading ? UI.SIGNING_IN : UI.SIGN_IN}
      </button>
    </form>
  );
}
