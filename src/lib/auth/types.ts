/**
 * types.ts — NextAuth TypeScript Type Augmentations
 *
 * ─── WHAT THIS FILE DOES ────────────────────────────────────────────────────
 *
 *  NextAuth's built-in Session and JWT types do not include custom fields
 *  like `id` or `role`. TypeScript's "declaration merging" (the `declare module`
 *  syntax below) lets us ADD new fields to existing interfaces defined in
 *  third-party packages without modifying their source code.
 *
 *  After this file is imported:
 *    session.user.id    → string (was missing from DefaultSession)
 *    session.user.role  → Role  (was missing from DefaultSession)
 *    token.id           → string (custom field added to JWT)
 *    token.role         → Role   (custom field added to JWT)
 *
 * ─── HOW DECLARATION MERGING WORKS ──────────────────────────────────────────
 *
 *  When TypeScript sees two `interface Session` declarations in the same
 *  module scope, it MERGES them into one combined interface. So:
 *
 *    // NextAuth's original (simplified):
 *    interface Session { user: { name, email, image } }
 *
 *    // Our augmentation:
 *    interface Session { user: { id: string; role: Role } & DefaultSession["user"] }
 *
 *    // Result TypeScript sees:
 *    interface Session { user: { id: string; role: Role; name, email, image } }
 *
 * ─── WHY THIS MATTERS ────────────────────────────────────────────────────────
 *
 *  Without this file, TypeScript would complain:
 *    Property 'role' does not exist on type 'Session["user"]'
 *  every time you write `session.user.role` in your components.
 *
 *  This file must be imported somewhere in the module graph before you
 *  access these fields. It is imported in config.ts via:
 *    import "@/lib/auth/types";
 */
import { Role } from "@/generated/prisma/enums";
import type { DefaultSession } from "next-auth";

declare module "next-auth" {
  interface Session {
    user: {
      id: string;
      role: Role;
    } & DefaultSession["user"];
  }

  interface User {
    role: Role;
  }
}

// NextAuth v5 bundles @auth/core internally — augment the JWT type there.
// "next-auth/jwt" re-exports from "@auth/core/jwt" but the augmentation
// target must be the module that actually declares the JWT interface.
declare module "@auth/core/jwt" {
  interface JWT {
    /** User's database ID — embedded in the token on sign-in. */
    id: string;
    /** User's role — embedded in the token via the jwt() callback. */
    role: Role;
    /**
     * Snapshot of the user's sessionVersion at sign-in time.
     * Compared against the DB value on every request; a mismatch means
     * the user triggered sign-out-all or reset their password — token revoked.
     */
    sessionVersion: number;
  }
}

export type { Role };
