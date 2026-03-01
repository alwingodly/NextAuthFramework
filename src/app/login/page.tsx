/**
 * app/login/page.tsx — Login Page (Server Component)
 *
 * ─── WHAT THIS PAGE DOES ────────────────────────────────────────────────────
 *
 *  Renders the sign-in form. Supports two methods:
 *    1. Google OAuth  — one-click, no password
 *    2. Credentials   — email + password
 *
 *  If the user is already logged in, it skips the form entirely and redirects
 *  them straight to their dashboard (admin → /admin, user → /user).
 *
 * ─── HOW IT WORKS ───────────────────────────────────────────────────────────
 *
 *  1. auth() reads the JWT cookie and returns the current session (or null).
 *  2. If session exists → redirect() immediately (no form rendered).
 *  3. If no session → render the login form.
 *
 *  The actual sign-in logic lives in:
 *    - SignInForm.tsx       → calls signIn("credentials", { email, password })
 *    - GoogleSignInButton   → calls signIn("google", { callbackUrl })
 *    - /api/auth/[...nextauth]/route.ts → NextAuth handles the POST
 *    - lib/auth/config.ts authorize() → validates, rate-limits, checks password
 *
 * ─── SECURITY ────────────────────────────────────────────────────────────────
 *
 *  OWASP A01: This page is in AUTH_ROUTES.publicPaths so proxy.ts skips it.
 *  The auth() check here is an extra guard — if someone is already logged in,
 *  we don't show them the login form (prevents session confusion).
 *
 *  No sensitive data is rendered here. Error states show only
 *  "Invalid email or password" — never which field was wrong.
 */
import { auth } from "@/auth";
import { redirect } from "next/navigation";
import Link from "next/link";
import { SignInForm } from "@/components/auth/SignInForm";
import { GoogleSignInButton } from "@/components/auth/GoogleSignInButton";
import { AUTH_ROUTES } from "@/lib/auth/config";
import { AUTH_FRAMEWORK_CONFIG } from "@/lib/auth/framework-config";
import { LOGIN_MESSAGES } from "@/lib/messages";
import { Role } from "@/generated/prisma/enums";

interface LoginPageProps {
  searchParams: Promise<{ message?: string }>;
}

export default async function LoginPage({ searchParams }: LoginPageProps) {
  // Already logged in → redirect to appropriate dashboard
  const session = await auth();
  if (session?.user) {
    redirect(
      session.user.role === Role.ADMIN
        ? AUTH_ROUTES.adminHome
        : AUTH_ROUTES.userHome
    );
  }

  const { message } = await searchParams;
  const feedbackMessage = message
    ? LOGIN_MESSAGES[message as keyof typeof LOGIN_MESSAGES]
    : null;

  return (
    <div className="flex min-h-screen items-center justify-center bg-zinc-50 dark:bg-zinc-950">
      <div className="w-full max-w-sm rounded-2xl border border-zinc-200 bg-white p-8 shadow-sm dark:border-zinc-800 dark:bg-zinc-900">
        {feedbackMessage && (
          <p className="mb-6 rounded-lg bg-green-50 px-4 py-3 text-sm text-green-700 dark:bg-green-950 dark:text-green-400">
            {feedbackMessage}
          </p>
        )}

        <div className="mb-8 text-center">
          <h1 className="text-2xl font-bold text-zinc-900 dark:text-zinc-100">
            Welcome back
          </h1>
          <p className="mt-1 text-sm text-zinc-500 dark:text-zinc-400">
            Sign in to your account
          </p>
        </div>

        <div className="flex flex-col gap-6">
          {AUTH_FRAMEWORK_CONFIG.providers.google && (
            <>
              <GoogleSignInButton />

              {AUTH_FRAMEWORK_CONFIG.providers.credentials && (
                <div className="flex items-center gap-3">
                  <div className="h-px flex-1 bg-zinc-200 dark:bg-zinc-700" />
                  <span className="text-xs text-zinc-400">or</span>
                  <div className="h-px flex-1 bg-zinc-200 dark:bg-zinc-700" />
                </div>
              )}
            </>
          )}

          {AUTH_FRAMEWORK_CONFIG.providers.credentials && <SignInForm />}

          <p className="text-center text-sm text-zinc-500 dark:text-zinc-400">
            Don&apos;t have an account?{" "}
            <Link
              href={AUTH_ROUTES.register}
              className="font-medium text-zinc-900 underline-offset-4 hover:underline dark:text-zinc-100"
            >
              Create one
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
}
