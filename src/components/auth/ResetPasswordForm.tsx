"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { resetPassword } from "@/app/actions/reset-password";
import { AUTH_ROUTES } from "@/lib/auth/routes";
import { RESET_PASSWORD_ERRORS, UI } from "@/lib/messages";

const PASSWORD_HINT = "Min. 8 characters \u00b7 uppercase \u00b7 lowercase \u00b7 number";

interface ResetPasswordFormProps {
  token: string;
  requireComplexity?: boolean;
}

export function ResetPasswordForm({ token, requireComplexity = false }: ResetPasswordFormProps) {
  const router = useRouter();
  const [error,   setError]   = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: React.SyntheticEvent<HTMLFormElement>) {
    e.preventDefault();
    setError("");
    setLoading(true);

    const formData = new FormData(e.currentTarget);
    // Embed the token from the URL (not a hidden input — keeps it off the DOM)
    formData.set("token", token);

    const result = await resetPassword(formData);
    setLoading(false);

    if (!result.success) {
      setError(result.error ?? RESET_PASSWORD_ERRORS.UPDATE_FAILED);
      return;
    }

    // Redirect to login with a success message via query param
    router.push(`${AUTH_ROUTES.login}?message=password-reset`);
  }

  return (
    <form onSubmit={handleSubmit} className="flex flex-col gap-4">
      <div className="flex flex-col gap-1">
        <label
          htmlFor="password"
          className="text-sm font-medium text-zinc-700 dark:text-zinc-300"
        >
          {UI.LABEL_NEW_PASSWORD}
        </label>
        <input
          id="password"
          name="password"
          type="password"
          required
          autoComplete="new-password"
          placeholder={UI.PLACEHOLDER_NEW_PASSWORD}
          className="rounded-lg border border-zinc-300 bg-white px-4 py-2.5 text-sm text-zinc-900 placeholder-zinc-400 outline-none focus:border-zinc-900 focus:ring-2 focus:ring-zinc-900/10 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-100 dark:focus:border-zinc-400"
        />
        {requireComplexity && (
          <p className="text-xs text-zinc-400 dark:text-zinc-500">
            {PASSWORD_HINT}
          </p>
        )}
      </div>

      <div className="flex flex-col gap-1">
        <label
          htmlFor="confirmPassword"
          className="text-sm font-medium text-zinc-700 dark:text-zinc-300"
        >
          {UI.LABEL_CONFIRM_PASSWORD}
        </label>
        <input
          id="confirmPassword"
          name="confirmPassword"
          type="password"
          required
          autoComplete="new-password"
          placeholder={UI.PLACEHOLDER_PASSWORD}
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
        {loading ? UI.RESETTING : UI.RESET_PASSWORD}
      </button>

      <p className="text-center text-sm text-zinc-500 dark:text-zinc-400">
        <Link
          href={AUTH_ROUTES.login}
          className="font-medium text-zinc-900 underline-offset-4 hover:underline dark:text-zinc-100"
        >
          {UI.BACK_TO_LOGIN}
        </Link>
      </p>
    </form>
  );
}
