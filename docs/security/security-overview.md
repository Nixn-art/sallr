# Security overview

SaulR is an Express application with PostgreSQL and a static browser client. All SQL uses parameter placeholders. Server-side ownership predicates protect listings and favorites; message queries are constrained to the authenticated participant.

## Active controls

- Passwords use bcrypt with cost 12; registration requires 10+ characters containing letters and numbers.
- Signed JWT sessions are HttpOnly, `SameSite=Lax`, eight hours by default, validated for issuer, audience, expiry, token type and revocation. `Secure` is enabled in production.
- State-changing browser requests require a double-submit CSRF token. Legacy bearer tokens remain accepted only for API compatibility.
- Login and registration are limited to 10 attempts per IP per 15 minutes. This in-memory control must be replaced with a shared store when more than one application instance is deployed.
- JSON has a 5 MB limit; text rejects markup/control characters; images accept only bounded PNG/JPEG/WebP data URLs.
- CSP, HSTS in production, anti-framing, MIME-sniffing, referrer and permissions policies are set centrally.
- Audit events record authentication and account events without credentials or tokens. Database audit storage should be append-only for the application role in production.

## Required production configuration

Set `NODE_ENV=production`, `DATABASE_URL`, and a unique `JWT_SECRET` of at least 32 random characters. Terminate TLS at a managed proxy/load balancer, force HTTPS there, set `SECURE_COOKIES=true`, and set `TRUST_PROXY=true` only when that proxy is trusted. Do not commit `.env`.

MFA, email verification, password recovery, roles, payments, multi-tenancy, queues, and caches do not exist in this application and were deliberately not added as speculative features. Add them with dedicated data models and security review when the corresponding product feature is introduced.
