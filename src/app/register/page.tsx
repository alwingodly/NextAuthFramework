/**
 * app/register/page.tsx — Registration Page (Server Component)
 *
 * ─── WHAT THIS PAGE DOES ────────────────────────────────────────────────────
 *
 *  Renders the sign-up form. Allows unauthenticated users to create a new
 *  account with an email and password.
 *
 *  If the user is already logged in, they are immediately redirected to their
 *  dashboard — no reason to show the register form again.
 *
 * ─── HOW IT WORKS ───────────────────────────────────────────────────────────
 *
 *  1. auth() checks for a valid JWT cookie.
 *  2. If session exists → redirect to /user or /admin.
 *  3. If no session → render RegisterForm.
 *
 *  The actual sign-up logic lives in:
 *    - RegisterForm.tsx      → collects and submits form data
 *    - actions/register.ts   → Server Action: validates, hashes, and writes to DB
 *
 * ─── SECURITY ────────────────────────────────────────────────────────────────
 *
 *  OWASP A01:
 *    This page is in AUTH_ROUTES.publicPaths so proxy.ts lets it through.
 *    The auth() check here prevents already-logged-in users from seeing it.
 *
 *  OWASP A07:
 *    All sensitive logic (rate limiting, password hashing, validation) runs
 *    entirely in the Server Action — this page is just a container.
 *
 *  NEW ACCOUNTS DEFAULT TO USER ROLE:
 *    The register Server Action never accepts a `role` from client input.
 *    Role defaults to USER at the Prisma schema level. Admin role can only
 *    be granted by being in the ADMIN_EMAILS list in lib/auth/config.ts
 *    (applied at OAuth login time), or by a direct DB update.
 */
import { auth } from "@/auth";
import { redirect } from "next/navigation";
import { RegisterForm } from "@/components/auth/RegisterForm";
import { GoogleSignInButton } from "@/components/auth/GoogleSignInButton";
import { AUTH_ROUTES } from "@/lib/auth/config";
import { AUTH_FRAMEWORK_CONFIG } from "@/lib/auth/framework-config";
import { Role } from "@/generated/prisma/enums";

export default async function RegisterPage() {
  // Already logged in → skip registration, go to dashboard
  const session = await auth();
  if (session?.user) {
    redirect(
      session.user.role === Role.ADMIN
        ? AUTH_ROUTES.adminHome
        : AUTH_ROUTES.userHome
    );
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-zinc-50 dark:bg-zinc-950">
      <div className="w-full max-w-sm rounded-2xl border border-zinc-200 bg-white p-8 shadow-sm dark:border-zinc-800 dark:bg-zinc-900">
        <div className="mb-8 text-center">
          <h1 className="text-2xl font-bold text-zinc-900 dark:text-zinc-100">
            Create an account
          </h1>
          <p className="mt-1 text-sm text-zinc-500 dark:text-zinc-400">
            Sign up to get started
          </p>
        </div>

        <div className="flex flex-col gap-6">
          {AUTH_FRAMEWORK_CONFIG.providers.google && (
            <>
              {/* Google OAuth — creates account automatically on first use */}
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

          {/* Email/password registration form */}
          {AUTH_FRAMEWORK_CONFIG.providers.credentials && (
            <RegisterForm
              requireComplexity={AUTH_FRAMEWORK_CONFIG.security.passwordRequireComplexity}
            />
          )}
        </div>
      </div>
    </div>
  );
}
