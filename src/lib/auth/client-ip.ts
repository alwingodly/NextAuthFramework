import { AUTH_FRAMEWORK_CONFIG } from "@/lib/auth/framework-config";

/**
 * Extract a stable client identifier for rate limiting.
 *
 * When proxy headers are untrusted, we intentionally collapse to "unknown"
 * rather than trusting spoofable request headers.
 */
export function getClientIp(headersList: Headers): string {
  if (!AUTH_FRAMEWORK_CONFIG.security.trustProxyHeaders) {
    // Without trusted proxy headers we cannot get a real IP. Use a weak
    // fingerprint so different browsers don't all collapse into one shared
    // rate-limit bucket (which would allow DoS on all users).
    // This fingerprint can be spoofed — enable AUTH_TRUST_PROXY_HEADERS=true
    // behind a known reverse proxy (Vercel, Cloudflare, nginx) for real IP isolation.
    const ua   = (headersList.get("user-agent")       ?? "").slice(0, 128);
    const lang = (headersList.get("accept-language")  ?? "").slice(0, 32);
    const fp   = `${ua}|${lang}`.replace(/\s+/g, " ").trim();
    return fp || "unknown";
  }

  const forwardedFor = headersList.get("x-forwarded-for");
  if (forwardedFor) {
    const firstIp = forwardedFor.split(",")[0]?.trim();
    if (firstIp) return firstIp;
  }

  const realIp = headersList.get("x-real-ip")?.trim();
  if (realIp) return realIp;

  return "unknown";
}
