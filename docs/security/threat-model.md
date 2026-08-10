# Threat model

| Threat | Surface | Mitigation | Residual risk |
|---|---|---|---|
| Credential stuffing | Login/register | bcrypt, password rules, IP rate limit, audit events | Distributed attacks require WAF/shared rate limiting and MFA. |
| Session theft/fixation | Browser session | Short-lived signed HttpOnly cookie, CSRF token, logout revocation | XSS remains a browser-wide risk; CSP and input restrictions reduce it. |
| IDOR/BOLA | Listings, favorites, messages | Auth middleware and owner/participant SQL predicates | New endpoints must follow the same pattern. |
| Injection/XSS | JSON and stored text | Parameterized SQL, strict JSON, bounded plain text, image allowlist, CSP | Client-side template rendering should be refactored to DOM APIs before rich text is supported. |
| CSRF | Cookie-authenticated mutations | SameSite cookies plus CSRF header | API clients using bearer tokens must apply their own origin controls. |
| Availability | Public/API endpoints | Request/body bounds and rate limits | In-memory limits do not span instances. |
| Audit tampering | Audit table | Separate event table, request IDs, restricted DB role recommended | Current hash chaining/immutable external sink is not implemented. |
| Secrets/supply chain | Repository/dependencies | `.env` ignored, example config, lockfile, CI audit/secret scan | Hosting secret manager and dependency-review ownership are operational requirements. |
