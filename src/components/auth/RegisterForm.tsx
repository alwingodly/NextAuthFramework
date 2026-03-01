/**
 * RegisterForm.tsx — Sign-Up Form (Client Component)
 *
 * ─── WHAT THIS COMPONENT DOES ────────────────────────────────────────────────
 *
 *  Renders the registration form with four fields:
 *    - Name (optional)
 *    - Email (required)
 *    - Password (required, min 8 chars)
 *    - Confirm Password (required, must match)
 *
 *  On submit, calls the `register` Server Action. On success, redirects to
 *  /login so the user can sign in with their new account.
 *
 * ─── FLOW ON SUBMIT ──────────────────────────────────────────────────────────
 *
 *  1. User fills the form → clicks "Create account"
 *  2. register(formData) is called (Server Action in actions/register.ts)
 *  3. Server validates, hashes, and writes to DB
 *  4. result.success → router.push("/login")
 *     result.error   → display inline error message
 *
 * ─── WHY A SERVER ACTION (not client-side fetch)? ────────────────────────────
 *
 *  - Automatically CSRF-protected by Next.js (no manual token needed)
 *  - Runs entirely on the server — password hash never touches the browser
 *  - Simpler than a REST endpoint for this use case
 *
 * ─── SECURITY ────────────────────────────────────────────────────────────────
 *
 *  This component is UI only. All real security lives in actions/register.ts:
 *    - Rate limiting (OWASP A07)
 *    - Server-side input validation (OWASP A03)
 *    - bcrypt hashing (OWASP A02)
 *    - Generic error messages (no user enumeration)
 *
 *  Client-side validation here is UX only — always re-validated on server.
 */
"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { register } from "@/app/actions/register";
import { AUTH_ROUTES } from "@/lib/auth/routes";
import { REGISTER_ERRORS, UI } from "@/lib/messages";

const PASSWORD_HINT = "Min. 8 characters \u00b7 uppercase \u00b7 lowercase \u00b7 number";

interface RegisterFormProps {
  requireComplexity?: boolean;
}

export function RegisterForm({ requireComplexity = false }: RegisterFormProps) {
  const router = useRouter();
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: React.SyntheticEvent<HTMLFormElement>) {
    e.preventDefault();
    setError("");
    setLoading(true);

    const formData = new FormData(e.currentTarget);
    const result = await register(formData);

    setLoading(false);

    if (!result.success) {
      setError(result.error ?? REGISTER_ERRORS.ACCOUNT_CREATION_FAILED);
      return;
    }

    // If email verification is required → show the "check your email" page
    if (result.data.requiresVerification) {
      router.push(AUTH_ROUTES.verifyEmail);
      return;
    }

    // No verification required → go to login with a success banner
    router.push(`${AUTH_ROUTES.login}?message=registered`);
  }

  return (
    <form onSubmit={handleSubmit} className="flex flex-col gap-4">
      {/* Name — optional */}
      <div className="flex flex-col gap-1">
        <label
          htmlFor="name"
          className="text-sm font-medium text-zinc-700 dark:text-zinc-300"
        >
          Name{" "}
          <span className="font-normal text-zinc-400">(optional)</span>
        </label>
        <input
          id="name"
          name="name"
          type="text"
          autoComplete="name"
          placeholder="Jane Smith"
          className="rounded-lg border border-zinc-300 bg-white px-4 py-2.5 text-sm text-zinc-900 placeholder-zinc-400 outline-none focus:border-zinc-900 focus:ring-2 focus:ring-zinc-900/10 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-100 dark:focus:border-zinc-400"
        />
      </div>

      {/* Email */}
      <div className="flex flex-col gap-1">
        <label
          htmlFor="email"
          className="text-sm font-medium text-zinc-700 dark:text-zinc-300"
        >
          Email
        </label>
        <input
          id="email"
          name="email"
          type="email"
          required
          autoComplete="email"
          placeholder="you@example.com"
          className="rounded-lg border border-zinc-300 bg-white px-4 py-2.5 text-sm text-zinc-900 placeholder-zinc-400 outline-none focus:border-zinc-900 focus:ring-2 focus:ring-zinc-900/10 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-100 dark:focus:border-zinc-400"
        />
      </div>

      {/* Password */}
      <div className="flex flex-col gap-1">
        <label
          htmlFor="password"
          className="text-sm font-medium text-zinc-700 dark:text-zinc-300"
        >
          Password
        </label>
        <input
          id="password"
          name="password"
          type="password"
          required
          autoComplete="new-password"
          placeholder="Min. 8 characters"
          className="rounded-lg border border-zinc-300 bg-white px-4 py-2.5 text-sm text-zinc-900 placeholder-zinc-400 outline-none focus:border-zinc-900 focus:ring-2 focus:ring-zinc-900/10 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-100 dark:focus:border-zinc-400"
        />
        {requireComplexity && (
          <p className="text-xs text-zinc-400 dark:text-zinc-500">
            {PASSWORD_HINT}
          </p>
        )}
      </div>

      {/* Confirm Password */}
      <div className="flex flex-col gap-1">
        <label
          htmlFor="confirmPassword"
          className="text-sm font-medium text-zinc-700 dark:text-zinc-300"
        >
          Confirm Password
        </label>
        <input
          id="confirmPassword"
          name="confirmPassword"
          type="password"
          required
          autoComplete="new-password"
          placeholder="••••••••"
          className="rounded-lg border border-zinc-300 bg-white px-4 py-2.5 text-sm text-zinc-900 placeholder-zinc-400 outline-none focus:border-zinc-900 focus:ring-2 focus:ring-zinc-900/10 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-100 dark:focus:border-zinc-400"
        />
      </div>

      {/* Inline error */}
      {error && (
        <p className="rounded-lg bg-red-50 px-4 py-2 text-sm text-red-600 dark:bg-red-950 dark:text-red-400">
          {error}
        </p>
      )}

      {/* Submit */}
      <button
        type="submit"
        disabled={loading}
        className="rounded-lg bg-zinc-900 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-zinc-700 disabled:opacity-50 dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-zinc-300"
      >
        {loading ? UI.CREATING_ACCOUNT : UI.CREATE_ACCOUNT}
      </button>

      {/* Link back to login */}
      <p className="text-center text-sm text-zinc-500 dark:text-zinc-400">
        Already have an account?{" "}
        <Link
          href={AUTH_ROUTES.login}
          className="font-medium text-zinc-900 underline-offset-4 hover:underline dark:text-zinc-100"
        >
          Sign in
        </Link>
      </p>
    </form>
  );
}
