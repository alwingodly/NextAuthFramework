"use client";

import { useState } from "react";
import Link from "next/link";
import { forgotPassword } from "@/app/actions/forgot-password";
import { AUTH_ROUTES } from "@/lib/auth/routes";
import { FORGOT_PASSWORD_ERRORS, FORGOT_PASSWORD_SUCCESS, UI } from "@/lib/messages";

export function ForgotPasswordForm() {
  const [error,   setError]   = useState("");
  const [success, setSuccess] = useState(false);
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: React.SyntheticEvent<HTMLFormElement>) {
    e.preventDefault();
    setError("");
    setLoading(true);

    const formData = new FormData(e.currentTarget);
    const result   = await forgotPassword(formData);

    setLoading(false);

    if (!result.success) {
      setError(result.error ?? FORGOT_PASSWORD_ERRORS.SEND_FAILED);
      return;
    }

    setSuccess(true);
  }

  if (success) {
    return (
      <p className="rounded-lg bg-green-50 px-4 py-3 text-sm text-green-700 dark:bg-green-950 dark:text-green-400">
        {FORGOT_PASSWORD_SUCCESS}
      </p>
    );
  }

  return (
    <form onSubmit={handleSubmit} className="flex flex-col gap-4">
      <div className="flex flex-col gap-1">
        <label
          htmlFor="email"
          className="text-sm font-medium text-zinc-700 dark:text-zinc-300"
        >
          {UI.LABEL_EMAIL}
        </label>
        <input
          id="email"
          name="email"
          type="email"
          required
          autoComplete="email"
          placeholder={UI.PLACEHOLDER_EMAIL}
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
        {loading ? UI.SENDING : UI.SEND_RESET_LINK}
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
