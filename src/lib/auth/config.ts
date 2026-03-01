/**
 * config.ts — Central Authentication Configuration
 *
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │  THIS IS THE ONLY FILE YOU NEED TO EDIT WHEN REUSING THIS FRAMEWORK.   │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * ─── WHAT THIS FILE DOES ────────────────────────────────────────────────────
 *
 *  1. Defines which auth PROVIDERS are active (Google, credentials, or both).
 *  2. Defines which emails are automatically promoted to ADMIN on first login.
 *  3. Defines the URL routes for login, user home, and admin home.
 *  4. Wires up NextAuth.js with:
 *       - Prisma adapter  → stores sessions, accounts, users in the database
 *       - JWT strategy    → each user gets a signed token stored in a cookie
 *       - Callbacks       → attach `role` to every JWT token and session
 *
 * ─── HOW AUTH FLOWS WORK ────────────────────────────────────────────────────
 *
 *  CREDENTIALS FLOW (email + password):
 *    Browser → POST /api/auth/callback/credentials
 *      → NextAuth calls `authorize()` below
 *        → rate limit check       (blocks brute force)
 *        → input validation       (blocks malformed input)
 *        → DB lookup by email     (Prisma parameterised query)
 *        → bcrypt.compare()       (constant-time password check)
 *      → if valid: jwt() callback embeds id + role into JWT
 *      → JWT is signed (HMAC-SHA256) and stored in HttpOnly cookie
 *      → Browser is redirected to userHome
 *
 *  GOOGLE OAUTH FLOW:
 *    Browser → GET /api/auth/signin/google
 *      → Redirect to Google consent screen
 *      → Google redirects back with one-time `code`
 *      → NextAuth exchanges code for user profile
 *      → NextAuth creates/updates User + Account in DB
 *      → jwt() checks email against ADMIN_EMAILS → assigns role
 *      → JWT cookie set → redirect to userHome
 *
 *  SESSION CHECK (every protected page load):
 *    Server component calls auth() → reads + verifies JWT cookie
 *      → Returns Session object with id, email, name, image, role
 *      → NO database query needed (stateless JWT)
 *
 * ─── SECURITY NOTES ─────────────────────────────────────────────────────────
 *
 *  OWASP A07 — Brute force protection (rate-limit.ts):
 *    Max 5 failed attempts per IP per 15 minutes.
 *    Generic error — never reveals "rate limited" vs "wrong password".
 *
 *  OWASP A02 — Cryptographic safety:
 *    bcrypt cost=12 ~ 300ms/attempt; JWT signed with AUTH_SECRET (HMAC-SHA256).
 *    Cookies are HttpOnly + SameSite=Lax + Secure (production).
 *
 *  OWASP A03 — Injection prevention:
 *    All DB queries via Prisma ORM. Server-side input validation before DB.
 *
 *  OWASP A01 — Broken access control:
 *    Role embedded in JWT server-side. Cannot be changed from the client.
 *    Admin promotion only via ADMIN_EMAILS allowlist (server-side).
 */

import { PrismaAdapter } from "@auth/prisma-adapter";
import bcrypt from "bcryptjs";
import { headers } from "next/headers";
import type { NextAuthConfig } from "next-auth";
import Credentials from "next-auth/providers/credentials";
import Google from "next-auth/providers/google";
import { db } from "@/lib/db";
import { Role } from "@/generated/prisma/enums";
import "@/lib/auth/types";
import {
  checkRateLimit,
  recordFailedAttempt,
  resetAttempts,
} from "@/lib/auth/rate-limit";
import { validateLoginCredentials } from "@/lib/auth/validation";
import { getClientIp } from "@/lib/auth/client-ip";
import {
  ADMIN_EMAILS,
  STAFF_EMAILS,
  AUTH_FRAMEWORK_CONFIG,
} from "@/lib/auth/framework-config";
// AUTH_ROUTES lives in routes.ts (no server-only imports) so that Client
// Components can safely import it without pulling next/headers into the bundle.
// We import it here for internal use and re-export it for backwards compat.
import { AUTH_ROUTES } from "@/lib/auth/routes";
export { AUTH_ROUTES };

// ─── PROVIDERS ────────────────────────────────────────────────────────────────

const providers: NextAuthConfig["providers"] = [];
const googleClientId = process.env.AUTH_GOOGLE_ID;
const googleClientSecret = process.env.AUTH_GOOGLE_SECRET;

if (AUTH_FRAMEWORK_CONFIG.providers.google) {
  /**
   * Google OAuth Provider
   *
   * Reads AUTH_GOOGLE_ID + AUTH_GOOGLE_SECRET from env automatically.
   * Scopes: openid, email, profile only. No access to calendar/contacts.
   *
   * FLOW:
   *   User clicks button → redirect to Google → consent → redirect back
   *   → NextAuth exchanges one-time code for user profile
   *   → Upserts User + Account rows → assigns role via jwt() callback
   *
   * SECURITY:
   *   OAuth state parameter prevents CSRF in the redirect loop.
   *   PKCE enabled by default in NextAuth v5.
   */
  if (!googleClientId || !googleClientSecret) {
    // Keep startup non-fatal in development, but surface a clear reason in logs.
    console.error(
      "[auth] Google provider is enabled but AUTH_GOOGLE_ID/AUTH_GOOGLE_SECRET is missing."
    );
  }

  providers.push(
    Google({
      clientId: googleClientId ?? "",
      clientSecret: googleClientSecret ?? "",
    })
  );
}

if (AUTH_FRAMEWORK_CONFIG.providers.credentials) {
  /**
   * Credentials Provider (email + password)
   *
   * SECURITY CHAIN (in order):
   *   1. Rate limit by IP    → max 5 failed attempts / 15 min
   *   2. Input validation    → type checks, length limits, email format
   *   3. DB lookup           → Prisma parameterised query (no SQL injection)
   *   4. Constant-time bcrypt.compare() → prevents timing oracle attacks
   *   5. Record outcome      → update rate limit counter
   *
   * Always returns null on failure — never an error string.
   * Returning null ensures the client gets a generic message regardless
   * of WHY the attempt failed (rate limit, bad email, bad password).
   * This prevents username enumeration attacks.
   */
  providers.push(
    Credentials({
      credentials: {
        email: { label: "Email", type: "email" },
        password: { label: "Password", type: "password" },
      },
      async authorize(credentials) {
        // ── 1. Rate limit by IP ──────────────────────────────────────────────
        // x-forwarded-for is set by proxies/CDNs (Vercel, Nginx, Cloudflare).
        // In production: ensure your reverse proxy is the only one that can
        // set this header, otherwise attackers can spoof their IP address.
        const headersList = await headers();
        const ip = getClientIp(headersList);

        const { allowed } = checkRateLimit(ip);
        if (!allowed) {
          return null; // Silently block — same response as wrong password
        }

        // ── 2. Input validation (before any DB access) ────────────────────────
        const { valid } = validateLoginCredentials(
          credentials?.email,
          credentials?.password
        );
        if (!valid) {
          recordFailedAttempt(ip);
          return null;
        }

        // ── 3. DB lookup (parameterised via Prisma ORM) ───────────────────────
        const user = await db.user.findUnique({
          where: { email: credentials.email as string },
        });

        // ── 4. Constant-time password comparison ─────────────────────────────
        // The DUMMY_HASH ensures bcrypt.compare() is called even when the user
        // doesn't exist. This means "email not found" and "wrong password"
        // both take ~300ms — an attacker cannot distinguish them by timing.
        const DUMMY_HASH =
          "$2b$12$zV/0aQ4o.fHiyKYFVSBPuemTASlHQ1fcbLp.as/Zy2ZFR2N8jHWsC";
        const passwordMatch = await bcrypt.compare(
          credentials.password as string,
          user?.password ?? DUMMY_HASH
        );

        if (!user || !user.password || !passwordMatch) {
          // ── 5a. Record failed attempt ──────────────────────────────────────
          recordFailedAttempt(ip);
          return null;
        }

        // ── 5b. Email verification check ──────────────────────────────────────
        // When AUTH_REQUIRE_EMAIL_VERIFICATION=true, block unverified accounts.
        // Google OAuth users always have emailVerified set (by Google).
        // This is a soft block — generic null keeps timing consistent.
        if (
          AUTH_FRAMEWORK_CONFIG.security.requireEmailVerification &&
          !user.emailVerified
        ) {
          // Not a brute-force attempt — don't count it against rate limit.
          return null;
        }

        // ── 5c. Success — clear rate limit ────────────────────────────────────
        resetAttempts(ip);

        return {
          id: user.id,
          email: user.email,
          name: user.name,
          image: user.image,
          role: user.role,
        };
      },
    })
  );
}

// ─── NEXTAUTH CONFIG ──────────────────────────────────────────────────────────

export const authConfig: NextAuthConfig = {
  /**
   * Prisma Adapter
   * Handles DB writes for User, Account, VerificationToken.
   * Session rows are NOT written (we use JWT strategy).
   * All queries are parameterised via Prisma — no SQL injection risk.
   */
  // Type cast needed: @auth/prisma-adapter and next-auth each bundle their own
  // copy of @auth/core, causing a structural type mismatch at compile time.
  // The cast is safe — the runtime behaviour is identical.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  adapter: PrismaAdapter(db) as any,

  /**
   * JWT Session Strategy
   *
   * User data is encoded in a signed JWT stored in a browser cookie.
   *
   * Cookie security (set by NextAuth automatically):
   *   HttpOnly   → JS cannot read it (blocks XSS cookie theft)
   *   SameSite=Lax → mitigates CSRF (blocks cross-origin POST)
   *   Secure     → HTTPS only in production
   *
   * Trade-off: JWT tokens cannot be instantly revoked.
   * For instant revocation, switch to strategy: "database".
   */
  session: {
    strategy: "jwt",
    maxAge: AUTH_FRAMEWORK_CONFIG.security.sessionMaxAgeSeconds,
  },
  trustHost: AUTH_FRAMEWORK_CONFIG.security.trustHost,

  pages: { signIn: AUTH_ROUTES.login },

  providers,

  callbacks: {
    /**
     * jwt() — runs on sign-in and on every auth() call thereafter.
     *
     * SIGN-IN: embeds id, role, and sessionVersion from the DB into the token.
     * SUBSEQUENT REQUESTS: validates token.sessionVersion against the DB value.
     *   If they differ (sign-out-all / password reset bumped the DB version),
     *   returns null → NextAuth treats the session as invalid → proxy.ts
     *   redirects to login. One indexed DB lookup per request.
     *
     * SECURITY: Role is set HERE server-side. The client cannot change it.
     * The token is SIGNED — tampering is detected on the next request.
     */
    async jwt({ token, user, account }) {
      // ── Sign-in: populate token from the DB user ──────────────────────────
      if (user) {
        token.id = user.id as string;
        token.role = user.role ?? Role.USER;

        // Embed sessionVersion so future requests can detect server-side revocation.
        const dbUser = await db.user.findUnique({
          where: { id: token.id as string },
          select: { sessionVersion: true },
        });
        token.sessionVersion = dbUser?.sessionVersion ?? 0;
      }

      // ── OAuth only: assign role and persist to DB ─────────────────────────
      // ADMIN_EMAILS takes precedence over STAFF_EMAILS.
      if (account && account.type !== "credentials" && token.email) {
        const email = token.email.toLowerCase();
        const isAdmin = ADMIN_EMAILS.includes(email);
        const isStaff = STAFF_EMAILS.includes(email);
        token.role = isAdmin ? Role.ADMIN : isStaff ? Role.STAFF : Role.USER;
        await db.user.update({
          where: { email: token.email },
          data: { role: token.role as Role },
        });
      }

      // ── Subsequent requests: enforce revocation via sessionVersion ─────────
      // Runs on every auth() call after sign-in (user is undefined then).
      // Returns null to invalidate the session if the DB version has advanced.
      if (!user && token.id) {
        const dbUser = await db.user.findUnique({
          where:  { id: token.id as string },
          select: { sessionVersion: true },
        });
        if (!dbUser || dbUser.sessionVersion !== (token.sessionVersion ?? -1)) {
          return null; // Session revoked — proxy.ts will redirect to /login
        }
      }

      return token;
    },

    /**
     * session() — called whenever auth() or useSession() reads the session.
     *
     * Copies id + role from the verified JWT token onto the session object
     * so they are available as session.user.id and session.user.role.
     *
     * SECURITY: Values come from the signature-verified JWT — not from the
     * client. No DB query here; that would defeat the purpose of JWT sessions.
     */
    async session({ session, token }) {
      // These values were set in jwt() above — casts are safe.
      session.user.id = token.id as string;
      session.user.role = token.role as Role;
      return session;
    },
  },
};
