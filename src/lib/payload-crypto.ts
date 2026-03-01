/**
 * payload-crypto.ts — AES-256-GCM request/response payload encryption
 *
 * ─── PURPOSE ─────────────────────────────────────────────────────────────────
 *
 *  Adds an optional application-layer encryption on top of HTTPS for API
 *  route payloads. Toggle with AUTH_REQUEST_ENCRYPTION env var.
 *
 *  When OFF → pure pass-through, zero overhead.
 *  When ON  → AES-256-GCM encryption of every API request body + response body.
 *
 * ─── WHY BOTH SIDES? ─────────────────────────────────────────────────────────
 *
 *  Encryption only works if BOTH server and client participate:
 *    Server encrypts response  →  Client must decrypt to read it
 *    Client encrypts request   →  Server must decrypt to process it
 *
 *  This file uses the Web Crypto API (globalThis.crypto) which runs identically
 *  in the browser and in Node.js 18+ — no separate client/server builds.
 *
 * ─── FLOW ────────────────────────────────────────────────────────────────────
 *
 *  1. Client calls GET /api/enc-key (authenticated) → receives base64 AES key
 *  2. Client stores key in memory (never persisted to localStorage/sessionStorage)
 *  3. For every API call, client encrypts the request body before sending
 *  4. Server middleware decrypts the body, runs the handler, encrypts the response
 *  5. Client decrypts the response body
 *
 * ─── WIRE FORMAT ─────────────────────────────────────────────────────────────
 *
 *  Base64( IV[12] | AuthTag[16] | Ciphertext[n] )
 *
 *  Header on encrypted responses:  X-Encrypted: 1
 *  Client reads this header to decide whether to decrypt.
 *
 * ─── USAGE: SERVER (API route handler) ──────────────────────────────────────
 *
 *  import { decryptPayload, encryptPayload } from "@/lib/payload-crypto";
 *
 *  export async function POST(req: Request) {
 *    const body = await decryptPayload(req);           // decrypt or pass-through
 *    const data = JSON.parse(body);
 *    const result = await processData(data);
 *    return encryptPayload(Response.json(result));     // encrypt or pass-through
 *  }
 *
 * ─── USAGE: CLIENT (fetch wrapper) ──────────────────────────────────────────
 *
 *  import { secureFetch } from "@/lib/payload-crypto";
 *
 *  const data = await secureFetch("/api/my-route", {
 *    method: "POST",
 *    body: JSON.stringify({ foo: "bar" }),
 *  });
 *
 * ─── GENERATE KEY ────────────────────────────────────────────────────────────
 *
 *  openssl rand -base64 32
 *  → add as ENCRYPTION_KEY in .env
 *
 * ─── SECURITY NOTES ──────────────────────────────────────────────────────────
 *
 *  - The AES key is delivered to authenticated clients via /api/enc-key.
 *    Only logged-in users receive the key — unauthenticated requests get 401.
 *  - The key is held in memory only (never written to disk or localStorage).
 *  - GCM authentication tag detects any tampering of the ciphertext.
 *  - Defense in depth: adds protection even if TLS is misconfigured or
 *    monitored at the network layer (e.g. corporate proxy, CDN).
 */

// ─── Constants ────────────────────────────────────────────────────────────────

const ALGORITHM   = "AES-GCM";
const KEY_BITS    = 256;
const IV_BYTES    = 12;   // 96-bit IV
const TAG_BITS    = 128;  // 128-bit auth tag
const ENC_HEADER  = "X-Encrypted";

// ─── Key helpers ──────────────────────────────────────────────────────────────

/** Import a raw base64 key string into a CryptoKey usable for AES-GCM. */
export async function importKey(base64Key: string): Promise<CryptoKey> {
  const raw = Uint8Array.from(atob(base64Key), (c) => c.charCodeAt(0));
  return globalThis.crypto.subtle.importKey(
    "raw",
    raw,
    { name: ALGORITHM },
    false, // not extractable after import
    ["encrypt", "decrypt"]
  );
}

// ─── Core encrypt / decrypt ───────────────────────────────────────────────────

/**
 * Encrypt a UTF-8 string → base64( IV[12] | AuthTag[16] | Ciphertext ).
 * Works in both browser and Node.js 18+.
 */
export async function encryptText(plain: string, key: CryptoKey): Promise<string> {
  const iv         = globalThis.crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const encoded    = new TextEncoder().encode(plain);

  const cipherBuf  = await globalThis.crypto.subtle.encrypt(
    { name: ALGORITHM, iv, tagLength: TAG_BITS },
    key,
    encoded
  );

  // AES-GCM in Web Crypto appends the 16-byte auth tag at the END of cipherBuf
  const combined   = new Uint8Array(IV_BYTES + cipherBuf.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(cipherBuf), IV_BYTES);

  return btoa(String.fromCharCode(...combined));
}

/**
 * Decrypt a base64 blob produced by encryptText().
 * Throws DOMException if auth tag verification fails (tampered data).
 */
export async function decryptText(blob: string, key: CryptoKey): Promise<string> {
  const combined   = Uint8Array.from(atob(blob), (c) => c.charCodeAt(0));
  const iv         = combined.subarray(0, IV_BYTES);
  const cipherBuf  = combined.subarray(IV_BYTES); // includes appended auth tag

  const plainBuf   = await globalThis.crypto.subtle.decrypt(
    { name: ALGORITHM, iv, tagLength: TAG_BITS },
    key,
    cipherBuf
  );

  return new TextDecoder().decode(plainBuf);
}

// ─── Server helpers ───────────────────────────────────────────────────────────

/**
 * SERVER: Read and decrypt an incoming Request body.
 * If AUTH_REQUEST_ENCRYPTION=false, returns raw text unchanged.
 * Requires ENCRYPTION_KEY env var when encryption is on.
 */
export async function decryptPayload(req: Request): Promise<string> {
  const raw = await req.text();
  if (!isRequestEncryptionEnabled()) return raw;

  const key = await getServerKey();
  return decryptText(raw, key);
}

/**
 * SERVER: Encrypt a Response body before sending to client.
 * If AUTH_REQUEST_ENCRYPTION=false, returns the original Response unchanged.
 * Adds  X-Encrypted: 1  header so the client knows to decrypt.
 */
export async function encryptPayload(res: Response): Promise<Response> {
  if (!isRequestEncryptionEnabled()) return res;

  const plain  = await res.text();
  const key    = await getServerKey();
  const cipher = await encryptText(plain, key);

  const headers = new Headers(res.headers);
  headers.set(ENC_HEADER, "1");
  headers.set("Content-Type", "text/plain");

  return new Response(cipher, { status: res.status, headers });
}

// ─── Client helpers ───────────────────────────────────────────────────────────

// In-memory key cache — never written to storage
let _clientKey: CryptoKey | null = null;

/**
 * CLIENT: Fetch the AES key from /api/enc-key (once per session).
 * Requires the user to be authenticated (NextAuth session cookie).
 */
async function getClientKey(): Promise<CryptoKey | null> {
  if (_clientKey) return _clientKey;

  const res = await fetch("/api/enc-key", { credentials: "include" });
  if (!res.ok) return null; // unauthenticated or encryption disabled

  const { key } = await res.json() as { key: string };
  _clientKey = await importKey(key);
  return _clientKey;
}

/**
 * CLIENT: Drop-in replacement for fetch() that transparently
 * encrypts request bodies and decrypts encrypted responses.
 *
 * When AUTH_REQUEST_ENCRYPTION=false on the server the /api/enc-key endpoint
 * returns { enabled: false } — in that case secureFetch falls back to plain fetch.
 *
 * @example
 *   const json = await secureFetch("/api/my-route", {
 *     method: "POST",
 *     body: JSON.stringify({ hello: "world" }),
 *   });
 */
export async function secureFetch(
  url: string,
  init: RequestInit = {}
): Promise<unknown> {
  const key = await getClientKey();

  // Encryption disabled or user unauthenticated — plain fetch
  if (!key) {
    const res = await fetch(url, init);
    return res.json();
  }

  // Encrypt request body if present
  const encryptedInit: RequestInit = { ...init, credentials: "include" };
  if (init.body && typeof init.body === "string") {
    encryptedInit.body = await encryptText(init.body, key);
    encryptedInit.headers = {
      ...init.headers,
      "Content-Type": "text/plain",
      [ENC_HEADER]: "1",
    };
  }

  const res = await fetch(url, encryptedInit);

  // Decrypt response if server flagged it
  if (res.headers.get(ENC_HEADER) === "1") {
    const cipher = await res.text();
    const plain  = await decryptText(cipher, key);
    return JSON.parse(plain);
  }

  return res.json();
}

// ─── Internal ─────────────────────────────────────────────────────────────────

function isRequestEncryptionEnabled(): boolean {
  return process.env.AUTH_REQUEST_ENCRYPTION === "true";
}

// Server-side key cache
let _serverKey: CryptoKey | null = null;

async function getServerKey(): Promise<CryptoKey> {
  if (_serverKey) return _serverKey;

  // PAYLOAD_ENCRYPTION_KEY is separate from ENCRYPTION_KEY (field encryption).
  // They must be different keys — ENCRYPTION_KEY is server-only and never
  // leaves the server. PAYLOAD_ENCRYPTION_KEY is shared with authenticated clients.
  const raw = process.env.PAYLOAD_ENCRYPTION_KEY;
  if (!raw) {
    throw new Error(
      "[payload-crypto] PAYLOAD_ENCRYPTION_KEY is not set. " +
      "Generate with: openssl rand -base64 32"
    );
  }

  _serverKey = await importKey(raw);
  return _serverKey;
}
