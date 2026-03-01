/**
 * GET /api/enc-key — Deliver the AES encryption key to authenticated clients
 *
 * ─── PURPOSE ─────────────────────────────────────────────────────────────────
 *
 *  The browser needs the AES key to encrypt requests and decrypt responses.
 *  This endpoint delivers it — but ONLY to authenticated users.
 *  Unauthenticated requests receive 401.
 *
 *  The key is stored in the client's memory (never localStorage/sessionStorage).
 *
 * ─── SECURITY ────────────────────────────────────────────────────────────────
 *
 *  - Auth check via NextAuth auth() — session cookie must be valid
 *  - If AUTH_REQUEST_ENCRYPTION=false, returns { enabled: false } (no key)
 *  - Cache-Control: no-store — browsers must not cache this response
 *  - The key is only as safe as the user's session; if a session is stolen
 *    the attacker can also get the key. This layer is defense-in-depth
 *    against passive network observers, not stolen sessions.
 */

import { auth } from "@/auth";
import { NextResponse } from "next/server";

export async function GET() {
  // ── 1. Auth check — only authenticated users get the key ──────────────────
  const session = await auth();
  if (!session?.user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  // ── 2. Return early if encryption is disabled ──────────────────────────────
  if (process.env.AUTH_REQUEST_ENCRYPTION !== "true") {
    return NextResponse.json(
      { enabled: false },
      {
        headers: {
          "Cache-Control": "no-store",
        },
      }
    );
  }

  // ── 3. Validate key is configured ─────────────────────────────────────────
  // IMPORTANT: PAYLOAD_ENCRYPTION_KEY is a separate key from ENCRYPTION_KEY.
  // ENCRYPTION_KEY is server-only (field encryption) and must NEVER be sent
  // to any client. PAYLOAD_ENCRYPTION_KEY is dedicated to payload encryption.
  const key = process.env.PAYLOAD_ENCRYPTION_KEY;
  if (!key) {
    console.error(
      "[enc-key] AUTH_REQUEST_ENCRYPTION=true but PAYLOAD_ENCRYPTION_KEY is not set."
    );
    return NextResponse.json(
      { error: "Encryption not configured" },
      { status: 500 }
    );
  }

  // ── 4. Return the key — client imports it into Web Crypto, not to disk ─────
  return NextResponse.json(
    { enabled: true, key },
    {
      headers: {
        // Never cache — every request should re-validate session
        "Cache-Control": "no-store, no-cache, must-revalidate",
        "Pragma": "no-cache",
      },
    }
  );
}
