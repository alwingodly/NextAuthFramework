/**
 * next.config.ts — Next.js configuration
 *
 * SECURITY: This file adds HTTP security headers to every response.
 * These headers are the first line of defence against common web attacks.
 *
 * HOW IT WORKS:
 *   Next.js reads `headers()` at build time and injects the returned headers
 *   into every matched response before it reaches the browser.
 *
 * OWASP COVERAGE:
 *   A05 Security Misconfiguration — secure defaults via HTTP headers
 */

import type { NextConfig } from "next";

// ─── Content Security Policy ─────────────────────────────────────────────────
// CSP is a browser instruction that tells it WHICH sources are allowed to load
// scripts, styles, images, fonts, and connections. This prevents XSS attacks.
//
// Directives explained:
//   default-src 'self'         → by default only load from our own origin
//   script-src  'self' ...     → allow Next.js runtime + inline scripts it injects
//   style-src   'self' ...     → allow Tailwind CSS inline styles
//   img-src     'self' data: https: → allow images from any HTTPS (avatars etc.)
//   font-src    'self' https://fonts.gstatic.com → Google Fonts (Geist font)
//   connect-src 'self'         → fetch() / WebSocket only to our origin
//   frame-ancestors 'none'     → nobody can embed this site in an <iframe>
const ContentSecurityPolicy = `
  default-src 'self';
  script-src 'self' ${process.env.NODE_ENV === "development" ? "'unsafe-eval' 'unsafe-inline'" : ""} https://accounts.google.com;
  style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;
  img-src 'self' data: https:;
  font-src 'self' https://fonts.gstatic.com;
  connect-src 'self' https://accounts.google.com;
  frame-src https://accounts.google.com;
  frame-ancestors 'none';
  base-uri 'self';
  form-action 'self';
  object-src 'none';
`
  .replace(/\s{2,}/g, " ") // collapse whitespace so it fits in one header line
  .trim();

// ─── Security Headers ─────────────────────────────────────────────────────────
const securityHeaders = [
  // Prevents browsers from guessing ("sniffing") the content type.
  // Without this, an attacker can upload a file that looks like an image
  // but is actually a script and get the browser to run it.
  // OWASP: A05 Security Misconfiguration
  {
    key: "X-Content-Type-Options",
    value: "nosniff",
  },

  // Prevents clickjacking — stops your page being embedded in someone else's
  // <iframe> to trick users into clicking on hidden buttons/links.
  // OWASP: A01 Broken Access Control (UI Redressing)
  {
    key: "X-Frame-Options",
    value: "DENY",
  },

  // Controls how much referrer info is sent when navigating to other sites.
  // "strict-origin-when-cross-origin" sends full path for same-origin but
  // only the origin (no path) for cross-origin — prevents leaking URLs with
  // tokens or IDs in the path to third parties.
  // OWASP: A02 Cryptographic Failures (info leakage)
  {
    key: "Referrer-Policy",
    value: "strict-origin-when-cross-origin",
  },

  // Restricts which browser APIs / hardware the page can access.
  // Each item disabled here prevents a compromised third-party script from
  // silently accessing the user's camera, mic, location, etc.
  // OWASP: A05 Security Misconfiguration
  {
    key: "Permissions-Policy",
    value: [
      "camera=()",       // no camera access
      "microphone=()",   // no mic access
      "geolocation=()",  // no GPS access
      "payment=()",      // no Payment Request API
      "usb=()",          // no USB access
    ].join(", "),
  },

  // HTTP Strict Transport Security (HSTS) — tells browsers to ONLY connect
  // over HTTPS for the next year, even if the user types "http://".
  // includeSubDomains extends this to all subdomains.
  // preload allows the domain to be built into browser HSTS lists.
  // NOTE: Only effective in production when served over HTTPS.
  // OWASP: A02 Cryptographic Failures (unencrypted transmission)
  {
    key: "Strict-Transport-Security",
    value: "max-age=31536000; includeSubDomains; preload",
  },

  // Content Security Policy — see explanation above.
  // This is the most powerful header for preventing XSS.
  // OWASP: A03 Injection (Cross-Site Scripting)
  {
    key: "Content-Security-Policy",
    value: ContentSecurityPolicy,
  },
];

const nextConfig: NextConfig = {
  reactCompiler: true,

  /**
   * headers() — applied to every route response.
   *
   * The `source: "/(.*)"` pattern matches ALL paths.
   * Each header in `securityHeaders` is added to every HTTP response.
   */
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: securityHeaders,
      },
    ];
  },
};

export default nextConfig;
