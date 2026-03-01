import Link from "next/link";
import { AUTH_ROUTES } from "@/lib/auth/config";
import { verifyEmail } from "@/app/actions/verify-email";
import { UI, VERIFY_EMAIL_SUCCESS, VERIFY_EMAIL_ERRORS } from "@/lib/messages";

interface VerifyEmailPageProps {
  searchParams: Promise<{ token?: string }>;
}

export default async function VerifyEmailPage({ searchParams }: VerifyEmailPageProps) {
  const { token } = await searchParams;

  // No token → show "check your inbox" holding page
  if (!token) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-zinc-50 dark:bg-zinc-950">
        <div className="w-full max-w-sm rounded-2xl border border-zinc-200 bg-white p-8 shadow-sm dark:border-zinc-800 dark:bg-zinc-900 text-center">
          <h1 className="text-2xl font-bold text-zinc-900 dark:text-zinc-100 mb-2">
            {UI.VERIFY_EMAIL_HEADING}
          </h1>
          <p className="text-sm text-zinc-500 dark:text-zinc-400">
            {UI.VERIFY_EMAIL_SUBHEADING}
          </p>
        </div>
      </div>
    );
  }

  // Token present → verify server-side immediately
  const result = await verifyEmail(token);

  return (
    <div className="flex min-h-screen items-center justify-center bg-zinc-50 dark:bg-zinc-950">
      <div className="w-full max-w-sm rounded-2xl border border-zinc-200 bg-white p-8 shadow-sm dark:border-zinc-800 dark:bg-zinc-900 text-center">
        {result.success ? (
          <>
            <p className="rounded-lg bg-green-50 px-4 py-3 text-sm text-green-700 dark:bg-green-950 dark:text-green-400 mb-6">
              {VERIFY_EMAIL_SUCCESS}
            </p>
            <Link
              href={AUTH_ROUTES.login}
              className="inline-block rounded-lg bg-zinc-900 px-6 py-2.5 text-sm font-semibold text-white transition hover:bg-zinc-700 dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-zinc-300"
            >
              {UI.SIGN_IN}
            </Link>
          </>
        ) : (
          <>
            <p className="rounded-lg bg-red-50 px-4 py-3 text-sm text-red-600 dark:bg-red-950 dark:text-red-400 mb-6">
              {result.error ?? VERIFY_EMAIL_ERRORS.INVALID_TOKEN}
            </p>
            <Link
              href={AUTH_ROUTES.login}
              className="text-sm font-medium text-zinc-900 underline-offset-4 hover:underline dark:text-zinc-100"
            >
              {UI.BACK_TO_LOGIN}
            </Link>
          </>
        )}
      </div>
    </div>
  );
}
