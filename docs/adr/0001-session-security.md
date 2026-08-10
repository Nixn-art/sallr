# ADR 0001: Cookie-backed short-lived sessions

Status: Accepted

## Context

The client previously stored a seven-day bearer token in local storage.

## Decision

Issue an eight-hour signed JWT in an HttpOnly, SameSite cookie; validate issuer/audience/type; use a readable CSRF token for mutations; revoke the current JWT at logout.

## Alternatives considered

Continue local-storage bearer tokens; or add a server-side session store. The cookie change is compatible with same-origin requests and avoids a new service.

## Consequences

Horizontal deployments must use shared revocation and rate-limit storage. Production requires TLS. Legacy bearer validation remains temporarily for API compatibility.

## Security/privacy implications

Reduces token exposure to script but requires CSRF protection and secure cookie deployment.
