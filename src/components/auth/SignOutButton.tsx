/**
 * SignOutButton.tsx — Sign Out Button (Client Component)
 *
 * ─── FLOW ON CLICK ───────────────────────────────────────────────────────────
 *
 *  1. User clicks → signOut({ callbackUrl: "/login" })
 *  2. NextAuth POSTs to /api/auth/signout (CSRF-protected endpoint)
 *  3. Server clears the JWT cookie (sets it to expired/empty)
 *  4. Browser is redirected to callbackUrl (/login)
 *  5. On next request, proxy.ts finds no session → sends back to /login
 *
 * ─── WHY POST (NOT GET) FOR SIGN-OUT? ───────────────────────────────────────
 *
 *  A GET-based sign-out endpoint could be abused by linking a user to an image
 *  or iframe that silently signs them out. NextAuth uses a POST with CSRF token
 *  to prevent this attack (OWASP A01 — Cross-Site Request Forgery on logout).
 *
 * ─── SECURITY ────────────────────────────────────────────────────────────────
 *
 *  After signOut(), the cookie is deleted client-side AND the server clears it.
 *  For JWT strategy: there is no server-side session to invalidate — the token
 *  simply disappears from the browser. If you need to immediately invalidate a
 *  session (e.g. "sign out all devices"), switch to database sessions.
 */
"use client";

import { signOut } from "next-auth/react";
import { AUTH_ROUTES } from "@/lib/auth/routes";

export function SignOutButton() {
  return (
    <button
      onClick={() => signOut({ callbackUrl: AUTH_ROUTES.login })}
      className="rounded-lg border border-zinc-300 px-4 py-2 text-sm font-medium text-zinc-700 transition hover:bg-zinc-100 dark:border-zinc-700 dark:text-zinc-300 dark:hover:bg-zinc-800"
    >
      Sign out
    </button>
  );
}
