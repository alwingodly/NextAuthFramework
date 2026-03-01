/**
 * result.ts — Generic ActionResult type for server actions
 *
 * ENTERPRISE PATTERN:
 *   All server actions return ActionResult<T> instead of throwing exceptions.
 *   This enforces a contract: callers MUST handle both success and failure.
 *   TypeScript discriminated unions guarantee type-safe access:
 *
 *     const result = await register(formData);
 *     if (!result.success) {
 *       result.error  // ← always string, never undefined here
 *       return;
 *     }
 *     result.data    // ← T is accessible only in success branch
 *
 * USAGE:
 *   import { type ActionResult, ok, fail } from "@/lib/result";
 *
 *   export async function myAction(): Promise<ActionResult<{ id: string }>> {
 *     try {
 *       const record = await db.create(...);
 *       return ok({ id: record.id });
 *     } catch {
 *       return fail(SOME_ERRORS.CREATION_FAILED);
 *     }
 *   }
 */

// ─── Core Type ────────────────────────────────────────────────────────────────

export type ActionResult<T = void> =
  | { success: true;  data: T }
  | { success: false; error: string };

// ─── Helper Factories ─────────────────────────────────────────────────────────

/** Return a successful result, optionally carrying data. */
export function ok(): ActionResult<void>;
export function ok<T>(data: T): ActionResult<T>;
export function ok<T>(data?: T): ActionResult<T> {
  return { success: true, data: data as T };
}

/** Return a failed result with a user-facing error message. */
export function fail<T = void>(error: string): ActionResult<T> {
  return { success: false, error };
}
