import { AUTH_FRAMEWORK_CONFIG } from "@/lib/auth/framework-config";

/**
 * rate-limit.ts — In-memory brute force protection for the login endpoint
 *
 * OWASP: A07 Identification and Authentication Failures
 *
 * WHY THIS EXISTS:
 *   Without rate limiting, an attacker can try thousands of passwords per
 *   second against a login form. This is called a "brute force" or
 *   "credential stuffing" attack. Even with bcrypt slowing things down,
 *   we must add a second layer of defence.
 *
 * HOW IT WORKS:
 *   1. Every failed login attempt is recorded with the client's IP address.
 *   2. If IP exceeds MAX_ATTEMPTS within WINDOW_MS, we block further attempts.
 *   3. After WINDOW_MS passes with no attempts, the record is cleared.
 *   4. Successful login resets the counter for that IP.
 *
 * SECURITY DESIGN CHOICES:
 *   - We track FAILED attempts only — not successful ones. This means a user
 *     who logs in successfully after a few mistakes is NOT penalised.
 *   - Error messages never reveal WHICH check failed (rate limit vs bad password)
 *     because that would let attackers know when they've been blocked.
 *   - We track by IP, not by email, to prevent username enumeration via
 *     differential rate-limit errors.
 *
 * PRODUCTION NOTE:
 *   This uses in-memory storage which resets on every server restart and
 *   does NOT share state across multiple server instances (horizontal scaling).
 *   For production with multiple instances, replace the Map with Redis:
 *
 *   import { Redis } from 'ioredis'
 *   const redis = new Redis(process.env.REDIS_URL)
 *   // Use redis.incr() and redis.expire() instead of the Map below.
 */

// ─── Configuration ────────────────────────────────────────────────────────────

/** Maximum failed login attempts before blocking. */
const MAX_ATTEMPTS = AUTH_FRAMEWORK_CONFIG.security.rateLimit.maxAttempts;

/**
 * Time window in milliseconds.
 * After this time since the FIRST failed attempt, the counter resets.
 * Default: 15 minutes.
 */
const WINDOW_MS = AUTH_FRAMEWORK_CONFIG.security.rateLimit.windowMs;

// ─── In-Memory Store ──────────────────────────────────────────────────────────

interface AttemptRecord {
  /** Number of failed attempts in the current window. */
  count: number;
  /** Timestamp (ms) of the first failed attempt in this window. */
  firstAttemptAt: number;
}

/**
 * Map of IP address → attempt record.
 *
 * NOTE: In Next.js with Turbopack (dev mode), this module may be hot-reloaded,
 * which resets the map. That's acceptable in development.
 */
const attempts = new Map<string, AttemptRecord>();

// ─── Public API ───────────────────────────────────────────────────────────────

export interface RateLimitResult {
  /** true = request is allowed, false = request is blocked */
  allowed: boolean;
  /**
   * How many attempts remain before being blocked.
   * -1 when blocked (already exceeded limit).
   */
  remaining: number;
  /**
   * When the rate limit window resets (Unix ms timestamp).
   * Only meaningful when `allowed` is false.
   */
  resetAt: number;
}

/**
 * checkRateLimit — call this BEFORE validating credentials.
 *
 * @param ip - The client's IP address (from request headers).
 * @returns RateLimitResult indicating whether to proceed.
 *
 * @example
 * const { allowed, remaining } = checkRateLimit(ip);
 * if (!allowed) return null; // silently reject
 */
export function checkRateLimit(ip: string): RateLimitResult {
  const now = Date.now();
  const record = attempts.get(ip);

  // No previous attempts — definitely allowed.
  if (!record) {
    return { allowed: true, remaining: MAX_ATTEMPTS - 1, resetAt: now + WINDOW_MS };
  }

  // Window expired — treat as a fresh start.
  if (now - record.firstAttemptAt > WINDOW_MS) {
    attempts.delete(ip);
    return { allowed: true, remaining: MAX_ATTEMPTS - 1, resetAt: now + WINDOW_MS };
  }

  // Within window — check count.
  if (record.count >= MAX_ATTEMPTS) {
    const resetAt = record.firstAttemptAt + WINDOW_MS;
    return { allowed: false, remaining: -1, resetAt };
  }

  return {
    allowed: true,
    remaining: MAX_ATTEMPTS - record.count - 1,
    resetAt: record.firstAttemptAt + WINDOW_MS,
  };
}

/**
 * recordFailedAttempt — call this AFTER a failed login.
 *
 * @param ip - The client's IP address.
 */
export function recordFailedAttempt(ip: string): void {
  const now = Date.now();
  const record = attempts.get(ip);

  if (!record || now - record.firstAttemptAt > WINDOW_MS) {
    // First failure in this window — create new record.
    attempts.set(ip, { count: 1, firstAttemptAt: now });
  } else {
    // Increment existing record.
    record.count += 1;
  }
}

/**
 * resetAttempts — call this AFTER a successful login.
 * Clears any failed attempt record so the user starts fresh.
 *
 * @param ip - The client's IP address.
 */
export function resetAttempts(ip: string): void {
  attempts.delete(ip);
}

/**
 * getAttemptsRemaining — for displaying feedback in the UI.
 *
 * @param ip - The client's IP address.
 * @returns Number of attempts remaining, or 0 if blocked.
 */
export function getAttemptsRemaining(ip: string): number {
  const { allowed, remaining } = checkRateLimit(ip);
  return allowed ? remaining : 0;
}
