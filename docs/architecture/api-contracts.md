# API contracts

All JSON errors have `error`, `code`, and `requestId`. Browser authentication uses the `session` HttpOnly cookie; every mutation also sends `X-CSRF-Token`. Authorization is enforced on the server.

| Endpoint | Purpose | Access |
|---|---|---|
| `POST /api/auth/register`, `login` | Create/sign in account | Rate limited |
| `POST /api/auth/logout` | Revoke current session | Auth + CSRF |
| `GET /api/listings`, seller routes | Browse marketplace | Public |
| Listing mutations | Create/manage own listings | Owner + CSRF |
| `/api/me`, favorites, messages | Personal account/data | Auth; mutations need CSRF |

List queries are bounded to 100 results. API versioning is not yet implemented; use `/api/v1` before a breaking public API change. No payment or idempotency-sensitive endpoint exists.
