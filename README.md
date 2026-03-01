# Next Auth Framework (Reusable)

This project is a reusable Next.js auth framework with:
- NextAuth v5 (`google` + `credentials` providers)
- Role-based authorization (`USER` / `ADMIN`)
- Route guarding in `proxy.ts`
- Registration + login with server-side validation and rate limiting
- Security headers + CSP defaults

## Quick Start

```bash
npm install
npm run dev
```

## Central Auth Configuration

Use these files as your single auth config surface when reusing in another project:
- `src/lib/auth/framework-config.ts` (server-only auth/security knobs)
- `src/lib/auth/routes.ts` (route paths shared by server + client)

### `framework-config.ts` (server-side)

Environment variables:

```bash
# Provider toggles
AUTH_ENABLE_GOOGLE=true
AUTH_ENABLE_CREDENTIALS=true

# Admin allowlist (comma-separated)
AUTH_ADMIN_EMAILS=admin@example.com,security@example.com

# Password hashing
AUTH_BCRYPT_COST=12
AUTH_TRUST_HOST=true

# Rate limiting
AUTH_RATE_LIMIT_MAX_ATTEMPTS=5
AUTH_RATE_LIMIT_WINDOW_MS=900000

# Trust x-forwarded-for / x-real-ip from your platform proxy
AUTH_TRUST_PROXY_HEADERS=true
```

### `routes.ts` (client + server)

Public route variables (optional):

```bash
NEXT_PUBLIC_AUTH_ROUTE_LOGIN=/login
NEXT_PUBLIC_AUTH_ROUTE_REGISTER=/register
NEXT_PUBLIC_AUTH_ROUTE_USER_HOME=/user
NEXT_PUBLIC_AUTH_ROUTE_ADMIN_HOME=/admin
```

## Security Notes

- CSP now blocks `unsafe-inline` and `unsafe-eval` scripts in production.
- In development, CSP relaxes scripts for local tooling compatibility.
- Seed script no longer uses weak default passwords.

## Seeding Users

```bash
SEED_ADMIN_PASSWORD='your-strong-admin-password' \
SEED_USER_PASSWORD='your-strong-user-password' \
npm run db:seed
```

If seed passwords are not provided, random passwords are generated and printed once.
