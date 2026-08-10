# Disaster recovery

Use encrypted provider-managed PostgreSQL backups with a documented retention period. Restrict restore and backup access to operations personnel, keep secrets in a managed secret store, and test a restore into an isolated environment at least quarterly. The runbook must cover DNS/TLS restoration, application deployment from a pinned commit, secret recovery, database restore verification, and revocation of compromised sessions. Record each drill and compare actual recovery to the approved RTO/RPO.
