/**
 * db.ts — Prisma Client Singleton
 *
 * ─── WHAT THIS FILE DOES ────────────────────────────────────────────────────
 *
 *  Exports a single `db` instance of PrismaClient that is shared across the
 *  entire application. Import and use it like this:
 *
 *    import { db } from "@/lib/db";
 *    const user = await db.user.findUnique({ where: { email } });
 *
 * ─── WHY A SINGLETON? ────────────────────────────────────────────────────────
 *
 *  Next.js in development mode uses Hot Module Replacement (HMR): when you
 *  save a file, modules are re-evaluated. If `db.ts` were re-evaluated on
 *  every save, a new PrismaClient (and new SQLite connection) would be created
 *  each time — quickly exhausting the connection limit.
 *
 *  The fix: store the instance on `globalThis`, which persists across HMR.
 *  In production, modules are evaluated once so this is a no-op there.
 *
 * ─── PRISMA 7 + DRIVER ADAPTER ───────────────────────────────────────────────
 *
 *  Prisma 7 removed the legacy query engine and requires an explicit
 *  Driver Adapter for direct database connections. For PostgreSQL, we use
 *  `@prisma/adapter-pg` which wraps the `pg` (node-postgres) library.
 *
 *  The adapter receives the DATABASE_URL from environment variables
 *  (set in .env → a PostgreSQL connection string).
 *
 * ─── SECURITY ────────────────────────────────────────────────────────────────
 *
 *  OWASP A03 — Injection:
 *    All database queries go through Prisma's query builder which uses
 *    parameterised statements. Never pass user input directly into raw SQL.
 *    If you need raw queries, use: db.$queryRaw`SELECT ... WHERE id = ${id}`
 *    (tagged template → parameterised). Never use db.$queryRawUnsafe().
 *
 *  The connection string should be in .env (gitignored) and never committed.
 *  In production, use a pooled connection string (e.g. Supabase/Neon pgBouncer)
 *  and ensure the DB server is not publicly accessible.
 */
import { PrismaClient } from "@/generated/prisma/client";
import { PrismaPg } from "@prisma/adapter-pg";
import { Pool } from "pg";

function createPrismaClient() {
  // Prisma 7 requires a Driver Adapter for direct connections.
  // Use DATABASE_URL (pgBouncer pooled) at runtime for efficient connection reuse.
  const pool = new Pool({ connectionString: process.env.DATABASE_URL });
  const adapter = new PrismaPg(pool);
  return new PrismaClient({ adapter });
}

// Singleton — prevents multiple instances during Next.js hot reload in dev
const globalForPrisma = globalThis as unknown as { prisma: PrismaClient };

export const db = globalForPrisma.prisma ?? createPrismaClient();

if (process.env.NODE_ENV !== "production") globalForPrisma.prisma = db;
