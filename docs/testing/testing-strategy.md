# Testing strategy

Run `npm test`, `npm run lint`, `npm run check`, and `npm audit --omit=dev` before release. Add integration coverage using an isolated PostgreSQL database for registration, CSRF, logout/revocation, owner-only listing updates/deletes, message-participant isolation, malformed IDs, input limits, and rate limits. E2E coverage should use a browser to exercise sign-up, login, listing, favorite, messaging, logout and deletion/export workflows.

Coverage should prioritize authentication, authorization, validation, and mutations; the project has no coverage gate yet because it had no prior test harness. CI runs syntax checks and dependency audit; expand it to a database-backed suite before production.

Load tests must be non-production and verify login throttling and listing search under the agreed capacity target. Simulate unavailable PostgreSQL and verify a 503 without internal details.
