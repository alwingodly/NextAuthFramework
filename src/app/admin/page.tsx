/**
 * app/admin/page.tsx — Admin Dashboard (Server Component, ADMIN only)
 *
 * ─── ACCESS CONTROL ─────────────────────────────────────────────────────────
 *  THREE layers of protection:
 *   1. proxy.ts    → redirects non-admins BEFORE render
 *   2. auth() here → second check in case proxy is misconfigured
 *   3. Prisma select → only returns non-sensitive fields (no password hash)
 *
 * ─── HOW IT WORKS ───────────────────────────────────────────────────────────
 *  1. auth() verifies JWT → get session (or null)
 *  2. No session → redirect /login
 *  3. role !== ADMIN → redirect /user
 *  4. db.user.findMany() → fetch all users → render table
 *
 *  The DB query uses `select` to limit returned fields (OWASP A04):
 *  We NEVER return the password hash to the UI, even accidentally.
 *
 * ─── EXTENDING THIS PAGE ────────────────────────────────────────────────────
 *  To add admin actions (change role, delete user), create Server Actions
 *  in a separate file. Always re-check role INSIDE each Server Action —
 *  never assume caller is admin just because they can see this page.
 */
import { auth } from "@/auth";
import { redirect } from "next/navigation";
import { SignOutButton } from "@/components/auth/SignOutButton";
import { AUTH_ROUTES } from "@/lib/auth/config";
import { Role } from "@/generated/prisma/enums";
import { db } from "@/lib/db";

export default async function AdminDashboard() {
  const session = await auth();
  if (!session?.user) redirect(AUTH_ROUTES.login);
  if (session.user.role !== Role.ADMIN) redirect(AUTH_ROUTES.userHome);

  // Example: fetch all users to display in admin panel
  const users = await db.user.findMany({
    select: { id: true, name: true, email: true, role: true, createdAt: true },
    orderBy: { createdAt: "desc" },
  });

  return (
    <div className="min-h-screen bg-zinc-50 dark:bg-zinc-950">
      <div className="mx-auto max-w-4xl p-8">
        {/* Header */}
        <div className="mb-8 flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-zinc-900 dark:text-zinc-100">
              Admin Panel
            </h1>
            <p className="mt-1 text-sm text-zinc-500 dark:text-zinc-400">
              Signed in as {session.user.email}
            </p>
          </div>
          <SignOutButton />
        </div>

        {/* Stats */}
        <div className="mb-8 grid grid-cols-2 gap-4 sm:grid-cols-3">
          <StatCard label="Total Users" value={users.length} />
          <StatCard
            label="Admins"
            value={users.filter((u) => u.role === Role.ADMIN).length}
          />
          <StatCard
            label="Regular Users"
            value={users.filter((u) => u.role === Role.USER).length}
          />
        </div>

        {/* Users table */}
        <div className="overflow-hidden rounded-xl border border-zinc-200 bg-white dark:border-zinc-800 dark:bg-zinc-900">
          <div className="border-b border-zinc-200 px-6 py-4 dark:border-zinc-800">
            <h2 className="font-semibold text-zinc-900 dark:text-zinc-100">
              Users
            </h2>
          </div>
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-zinc-50 text-left dark:bg-zinc-800/50">
                <th className="px-6 py-3 font-medium text-zinc-500">Name</th>
                <th className="px-6 py-3 font-medium text-zinc-500">Email</th>
                <th className="px-6 py-3 font-medium text-zinc-500">Role</th>
                <th className="px-6 py-3 font-medium text-zinc-500">Joined</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-100 dark:divide-zinc-800">
              {users.map((user) => (
                <tr key={user.id}>
                  <td className="px-6 py-3 text-zinc-900 dark:text-zinc-100">
                    {user.name ?? "—"}
                  </td>
                  <td className="px-6 py-3 text-zinc-600 dark:text-zinc-400">
                    {user.email}
                  </td>
                  <td className="px-6 py-3">
                    <span
                      className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${
                        user.role === Role.ADMIN
                          ? "bg-purple-50 text-purple-700 dark:bg-purple-950 dark:text-purple-300"
                          : "bg-blue-50 text-blue-700 dark:bg-blue-950 dark:text-blue-300"
                      }`}
                    >
                      {user.role}
                    </span>
                  </td>
                  <td className="px-6 py-3 text-zinc-500 dark:text-zinc-400">
                    {user.createdAt.toLocaleDateString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {users.length === 0 && (
            <p className="px-6 py-8 text-center text-sm text-zinc-400">
              No users yet.
            </p>
          )}
        </div>
      </div>
    </div>
  );
}

function StatCard({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-xl border border-zinc-200 bg-white p-4 dark:border-zinc-800 dark:bg-zinc-900">
      <p className="text-sm text-zinc-500 dark:text-zinc-400">{label}</p>
      <p className="mt-1 text-2xl font-bold text-zinc-900 dark:text-zinc-100">
        {value}
      </p>
    </div>
  );
}
