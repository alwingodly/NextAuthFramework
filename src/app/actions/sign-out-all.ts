"use server";

import { db } from "@/lib/db";
import { auth, signOut } from "@/auth";
import { type ActionResult, ok, fail } from "@/lib/result";

/**
 * signOutAll — invalidates all active sessions for the current user.
 *
 * HOW IT WORKS:
 *   Increments `sessionVersion` on the User row. Any JWT token whose embedded
 *   `sessionVersion` doesn't match the DB value is considered stale.
 *
 * LIMITATION (JWT trade-off):
 *   Because proxy.ts doesn't query the DB on every request (Edge runtime
 *   limitation), other active sessions expire naturally within the configured
 *   AUTH_SESSION_MAX_AGE_SECONDS window. The current session is signed out
 *   immediately. For instant revocation across all sessions, replace the
 *   JWT strategy with strategy: "database" or use Redis.
 *
 * RECOMMENDATION:
 *   Set AUTH_SESSION_MAX_AGE_SECONDS=3600 (1 hour) to limit the window.
 */
export async function signOutAll(): Promise<ActionResult<void>> {
  const session = await auth();

  if (!session?.user?.id) {
    return fail("Not authenticated.");
  }

  // Increment sessionVersion — all JWTs with an older version become stale
  await db.user.update({
    where: { id: session.user.id },
    data:  { sessionVersion: { increment: 1 } },
  });

  // Sign out the current session (clears the cookie)
  await signOut({ redirect: false });

  return ok();
}
