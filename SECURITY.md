# Security policy

## Supported versions

Security fixes are applied to the latest released version and the current `main` branch. Development snapshots and older releases should not be assumed to receive backports unless a maintainer explicitly announces one.

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability. Use the repository's [private vulnerability reporting form](https://github.com/eddie-energy/hivemq-auth-plugin/security/advisories/new) and include:

- the affected version or commit;
- prerequisites and a minimal reproduction;
- expected and observed behavior;
- the likely security impact; and
- any suggested mitigation, if known.

Avoid including live credentials, private keys, production hostnames, or customer data. A maintainer can request additional details through the private advisory. Public disclosure should wait until a fix and release plan have been coordinated.

## Security-relevant behavior

The extension is designed to fail closed. It rejects missing credentials and connection principals, invalid topic filters, database failures, managed-executor rejection, and callback timeouts. MQTT client values are bound through prepared statements, while SQL templates are trusted deployment configuration.

Authentication and authorization decisions may remain cached until their configured TTL plus jitter expires. Outbound publish interception re-checks subscribe rules after cache expiry, including for existing subscriptions. In a multi-node deployment, cache expiry is local to each node.

The bundled TLS listener provides server authentication and does not request client certificates. Enabling it does not disable the plaintext listener. Operators requiring TLS-only access must expose only port 8883 and enforce that boundary with their service and network policy.

The credentials in `compose.yaml` and `docker/e2e/init.sql` are intentionally local test fixtures. They must never be reused outside disposable development environments.
