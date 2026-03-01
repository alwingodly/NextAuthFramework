/**
 * auth.ts — NextAuth Instance (single source of truth for the app)
 *
 * ─── EXPORTS ────────────────────────────────────────────────────────────────
 *
 *  auth      — Read the session in Server Components and proxy.ts.
 *              Usage: const session = await auth();
 *              Returns Session | null. Does NOT hit the database (JWT).
 *
 *  handlers  — { GET, POST } for app/api/auth/[...nextauth]/route.ts.
 *              Handles all NextAuth API endpoints:
 *                GET  /api/auth/session        → returns session JSON
 *                GET  /api/auth/signin/google  → redirects to Google
 *                GET  /api/auth/callback/google → OAuth callback
 *                POST /api/auth/callback/credentials → login form
 *                POST /api/auth/signout        → clears cookie
 *
 *  signIn    — Server Action: programmatic sign-in (not used in this project).
 *  signOut   — Server Action: used in SignOutButton via next-auth/react.
 *
 * ─── HOW auth() WORKS ───────────────────────────────────────────────────────
 *
 *   1. Reads the HttpOnly JWT cookie from the incoming request.
 *   2. Verifies the HMAC-SHA256 signature with AUTH_SECRET.
 *      → If invalid/missing: returns null.
 *   3. Decodes the payload → { id, email, name, image, role, expires }.
 *   4. Returns the Session object (no DB query — pure JWT decode).
 *
 * ─── SECURITY ────────────────────────────────────────────────────────────────
 *
 *   The JWT is signed with AUTH_SECRET (HMAC-SHA256).
 *   → Tampering with the cookie breaks the signature → auth() returns null.
 *   → The cookie is HttpOnly → JS cannot read it → XSS cannot steal it.
 *   ⚠  If AUTH_SECRET leaks: rotate it immediately. All sessions are invalidated.
 */
import NextAuth from "next-auth";
import { authConfig } from "@/lib/auth/config";

export const { auth, handlers, signIn, signOut } = NextAuth(authConfig);
