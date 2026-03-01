/**
 * proxy.ts — Route Guard (Next.js 16 Proxy)
 *
 * ─── WHAT THIS FILE DOES ────────────────────────────────────────────────────
 *
 *  Runs BEFORE every matched route is rendered. It checks authentication and
 *  authorization, then either lets the request through or redirects it.
 *  Think of it as a security checkpoint at the entrance to your app.
 *
 * ─── DECISION LOGIC (in order) ──────────────────────────────────────────────
 *
 *   1. Is the path public (/login, /api/auth)?  → let through immediately
 *   2. No valid JWT cookie?                     → redirect to /login
 *   3. Admin path + user is not ADMIN?          → redirect to /user
 *   4. All checks pass                          → let through
 *
 * ─── HOW auth() WRAPS THE HANDLER ───────────────────────────────────────────
 *
 *  `auth(callback)` is a NextAuth helper that reads + verifies the JWT cookie
 *  automatically, then calls our callback with `req.auth` pre-populated.
 *  We don't manually verify the JWT — NextAuth handles that.
 *
 * ─── SECURITY (OWASP A01 — Broken Access Control) ───────────────────────────
 *
 *  This is the FIRST layer of protection. Server components also call auth()
 *  independently (defence in depth) so even if this proxy were somehow
 *  bypassed, protected pages still guard themselves.
 *
 *  Role comes from the verified JWT — the client cannot forge it.
 *  Protected pages don't begin rendering for unauthenticated users,
 *  preventing accidental data leaks from render-time DB queries.
 *
 * ─── MATCHER ────────────────────────────────────────────────────────────────
 *
 *  Excludes: _next/static, _next/image, favicon.ico, and any file with an
 *  extension (.png, .svg, etc.). Everything else runs through this proxy.
 */
import { auth } from "@/auth";
import { NextResponse } from "next/server";
import { AUTH_ROUTES } from "@/lib/auth/config";
import { Role } from "@/generated/prisma/enums";

export default auth((req) => {
  const { nextUrl, auth: session } = req;
  const pathname = nextUrl.pathname;

  // Allow public paths through — use exact or segment-safe match to prevent
  // "/api/auth" from accidentally matching "/api/authenticate" etc.
  const isPublic = AUTH_ROUTES.publicPaths.some(
    (p) => pathname === p || pathname.startsWith(p + "/")
  );
  if (isPublic) return NextResponse.next();

  // Not authenticated → redirect to login
  if (!session?.user) {
    return NextResponse.redirect(new URL(AUTH_ROUTES.login, nextUrl));
  }

  // Authenticated but not ADMIN → block admin routes
  const isAdminPath = AUTH_ROUTES.adminPaths.some(
    (p) => pathname === p || pathname.startsWith(p + "/")
  );
  if (isAdminPath && session.user.role !== Role.ADMIN) {
    return NextResponse.redirect(new URL(AUTH_ROUTES.userHome, nextUrl));
  }

  // Authenticated but not STAFF or ADMIN → block staff routes
  const isStaffPath = AUTH_ROUTES.staffPaths.some(
    (p) => pathname === p || pathname.startsWith(p + "/")
  );
  if (isStaffPath && session.user.role !== Role.STAFF && session.user.role !== Role.ADMIN) {
    return NextResponse.redirect(new URL(AUTH_ROUTES.userHome, nextUrl));
  }

  return NextResponse.next();
});

export const config = {
  // Run middleware on all routes except static files and Next.js internals
  matcher: ["/((?!_next/static|_next/image|favicon.ico|.*\\..*).*)"],
};
