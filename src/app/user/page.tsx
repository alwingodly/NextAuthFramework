/**
 * app/user/page.tsx — User Dashboard (Server Component)
 *
 * ─── WHAT THIS PAGE DOES ────────────────────────────────────────────────────
 *
 *  A protected dashboard accessible to ALL authenticated users (USER + ADMIN).
 *  Displays the signed-in user's name, email, avatar, and role.
 *
 * ─── HOW IT WORKS ───────────────────────────────────────────────────────────
 *
 *  1. auth() verifies the JWT cookie → returns Session or null.
 *  2. If null → redirect to /login.
 *  3. Otherwise → render the dashboard with session.user data.
 *
 *  Session data available: { id, name, email, image, role }
 *  All data comes from the signed JWT — no DB query on this page.
 *
 * ─── DUAL PROTECTION (defence in depth) ─────────────────────────────────────
 *
 *  This page has TWO layers of auth protection:
 *
 *    Layer 1 — proxy.ts (network level):
 *      Runs before rendering. Redirects unauthenticated requests to /login.
 *      Fast — no page code runs at all if the user isn't logged in.
 *
 *    Layer 2 — auth() check here (application level):
 *      Runs at render time. Guards against edge cases where the proxy
 *      might be misconfigured or bypassed.
 *
 *  Never rely on only one layer. Always check auth() in sensitive pages.
 *
 * ─── HOW TO ADD YOUR CONTENT ────────────────────────────────────────────────
 *
 *  Replace the placeholder div at the bottom with your actual page content.
 *  Since this is a Server Component, you can query the DB directly:
 *
 *    const items = await db.item.findMany({ where: { userId: session.user.id } });
 */
import { auth } from "@/auth";
import { redirect } from "next/navigation";
import { SignOutButton } from "@/components/auth/SignOutButton";
import { AUTH_ROUTES } from "@/lib/auth/config";

export default async function UserDashboard() {
  const session = await auth();
  if (!session?.user) redirect(AUTH_ROUTES.login);

  const { name, email, image, role } = session.user;

  return (
    <div className="flex min-h-screen items-center justify-center bg-zinc-50 dark:bg-zinc-950">
      <div className="w-full max-w-md rounded-2xl border border-zinc-200 bg-white p-8 shadow-sm dark:border-zinc-800 dark:bg-zinc-900">
        {/* Header */}
        <div className="mb-6 flex items-center justify-between">
          <h1 className="text-xl font-bold text-zinc-900 dark:text-zinc-100">
            Dashboard
          </h1>
          <SignOutButton />
        </div>

        {/* User info */}
        <div className="flex items-center gap-4 rounded-xl bg-zinc-50 p-4 dark:bg-zinc-800">
          {image ? (
            // eslint-disable-next-line @next/next/no-img-element
            <img
              src={image}
              alt={name ?? "User"}
              className="h-12 w-12 rounded-full"
            />
          ) : (
            <div className="flex h-12 w-12 items-center justify-center rounded-full bg-zinc-200 text-lg font-semibold text-zinc-600 dark:bg-zinc-700 dark:text-zinc-300">
              {name?.[0]?.toUpperCase() ?? "U"}
            </div>
          )}
          <div>
            <p className="font-semibold text-zinc-900 dark:text-zinc-100">
              {name ?? "Unknown"}
            </p>
            <p className="text-sm text-zinc-500 dark:text-zinc-400">{email}</p>
          </div>
        </div>

        {/* Role badge */}
        <div className="mt-4 flex items-center gap-2">
          <span className="text-sm text-zinc-500 dark:text-zinc-400">Role:</span>
          <span className="inline-flex items-center rounded-full bg-blue-50 px-3 py-0.5 text-xs font-medium text-blue-700 dark:bg-blue-950 dark:text-blue-300">
            {role}
          </span>
        </div>

        {/* Content placeholder */}
        <div className="mt-6 rounded-xl border border-dashed border-zinc-300 p-6 text-center text-sm text-zinc-400 dark:border-zinc-700">
          Your app content goes here
        </div>
      </div>
    </div>
  );
}
