/**
 * routes.ts — Auth Route Constants
 *
 * ─── WHY THIS IS A SEPARATE FILE ────────────────────────────────────────────
 *
 *  `config.ts` uses `next/headers` (server-only API) for reading the client IP
 *  during rate limiting. This means `config.ts` cannot be imported by Client
 *  Components — doing so would try to pull a server-only module into the
 *  browser bundle, causing a build error.
 *
 *  Client Components like GoogleSignInButton and SignOutButton only need
 *  the route strings (e.g. "/login", "/user"). By keeping those here —
 *  with zero server-only imports — they can safely import this file.
 *
 * ─── IMPORT RULES ───────────────────────────────────────────────────────────
 *
 *  ✅ Safe to import from: Server Components, Client Components, proxy.ts
 *  ✅ Safe to import from: lib/auth/config.ts
 *
 *  This file must NEVER import from "next/headers", "next/cookies",
 *  or any other server-only module.
 */

export const AUTH_ROUTES = {
  login:         process.env.NEXT_PUBLIC_AUTH_ROUTE_LOGIN     ?? "/login",
  register:      process.env.NEXT_PUBLIC_AUTH_ROUTE_REGISTER  ?? "/register",
  userHome:      process.env.NEXT_PUBLIC_AUTH_ROUTE_USER_HOME  ?? "/user",
  staffHome:     process.env.NEXT_PUBLIC_AUTH_ROUTE_STAFF_HOME ?? "/staff",
  adminHome:     process.env.NEXT_PUBLIC_AUTH_ROUTE_ADMIN_HOME ?? "/admin",
  forgotPassword: "/forgot-password",
  resetPassword:  "/reset-password",
  verifyEmail:    "/verify-email",
  /** Paths that bypass authentication in proxy.ts. Be conservative. */
  publicPaths: [
    process.env.NEXT_PUBLIC_AUTH_ROUTE_LOGIN    ?? "/login",
    process.env.NEXT_PUBLIC_AUTH_ROUTE_REGISTER ?? "/register",
    "/api/auth",
    "/forgot-password",
    "/reset-password",
    "/verify-email",
  ],
  /** Paths that require STAFF or ADMIN role. */
  staffPaths: [process.env.NEXT_PUBLIC_AUTH_ROUTE_STAFF_HOME ?? "/staff"],
  /** Paths that require ADMIN role only. */
  adminPaths: [process.env.NEXT_PUBLIC_AUTH_ROUTE_ADMIN_HOME ?? "/admin"],
} as const;
