# EDDIE HiveMQ PostgreSQL authentication

This repository builds a HiveMQ Community Edition image and an installable extension with PostgreSQL-backed MQTT authentication and authorization.

The container image is based on HiveMQ CE 2026.5, and the extension targets HiveMQ Extension SDK 4.52. It supports:

- bcrypt password hashes from `aiida.aiida_mqtt_user`;
- `is_superuser` database users with unrestricted topic access;
- `ALLOW` publish and subscribe rows from `aiida.aiida_mqtt_acl`;
- an optional local superuser, configured with `HIVEMQ_LOCAL_SUPERUSER_USERNAME` and `AIIDA_MQTT_PASSWORD`;
- bounded PostgreSQL connection pooling and fail-closed asynchronous callbacks;
- independent authentication and ACL caches with TTL and jitter;
- outbound read checks, so ACL expiry also applies to already-active subscriptions;
- MQTT wildcard, shared-subscription, and `$SYS` topic rules; and
- configurable database settings and SQL templates.

Anonymous connections, missing credentials, database errors, callback timeouts, invalid ACL filters, and missing authorization state are denied.

## Build and test

Requirements are Java 21, Maven 3.9 or later, and Docker with Compose v2. Docker is also required by the Testcontainers-based PostgreSQL integration tests.

```sh
mvn --batch-mode --no-transfer-progress verify
```

`verify` runs unit tests, real PostgreSQL integration tests through Testcontainers, Javadoc validation, JaCoCo coverage gates (90% line and 80% branch), SpotBugs at maximum effort, compiler warnings as errors, and dependency-convergence checks. It produces:

- `target/eddie-mqtt-auth-hivemq-1.0.0-SNAPSHOT-all.jar` — the extension and runtime dependencies;
- `target/eddie-mqtt-auth-hivemq-1.0.0-SNAPSHOT-distribution.zip` — a directory ready to extract under a HiveMQ `extensions/` directory;
- `target/site/jacoco/index.html` — the browsable coverage report; and
- `target/site/apidocs/index.html` — generated public API documentation.

Extract the distribution ZIP into HiveMQ's `extensions/` directory. It contains an `eddie-mqtt-auth-hivemq/` directory with the extension JAR, metadata, default configuration, license, and third-party notices.

Build the container image with:

```sh
docker build -t eddie-mqtt-auth-hivemq:local .
```

Run the complete PostgreSQL, HiveMQ, MQTT ACL, active-subscription revocation, superuser, and TLS test with:

```sh
docker compose up --build --wait hivemq
docker compose --profile test run --build --no-deps --rm mqtt-test
docker compose --profile test down --volumes
```

The final command removes the test containers and volumes; run it after a failed test as well. For manual testing, `docker compose up --build` exposes MQTT on `localhost:18883` and MQTTS on `localhost:18884`. Override those host ports with `HIVEMQ_MQTT_PORT` and `HIVEMQ_MQTTS_PORT`.

Report suspected vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## Schema and query contract

The default queries target the following schema:

```sql
SELECT password_hash
FROM aiida.aiida_mqtt_user
WHERE username = ?
LIMIT 1;

SELECT count(*)
FROM aiida.aiida_mqtt_user
WHERE username = ? AND is_superuser = true;

SELECT topic
FROM aiida.aiida_mqtt_acl
WHERE username = ? AND acl_type = 'ALLOW' AND action = ?;
```

The SQL is operator-controlled configuration. Client data is always passed through JDBC prepared-statement parameters:

- the password query takes one username parameter and returns the bcrypt hash in column 1;
- the superuser query takes one username parameter and returns a boolean, numeric count, or boolean-like string in column 1;
- the ACL query takes username and action parameters, in that order, and returns topic filters in column 1.

Use JDBC `?` placeholders, not PostgreSQL `$1`/`$2` placeholders. The default action values are `PUBLISH` and `SUBSCRIBE`. Only `acl_type = 'ALLOW'` rows participate; `DENY` rows are not an override mechanism.

Passwords must be bcrypt strings using the `$2a$`, `$2b$`, or `$2y$` form.

## Runtime configuration

The bundled extension reads `extension.properties`. `${NAME}` denotes a required environment variable and `${NAME:default}` supplies a default. Set `HIVEMQ_AUTH_CONFIG` to use a different properties file.

### PostgreSQL

| Environment variable | Default |
| --- | --- |
| `HIVEMQ_DB_URL` | `jdbc:postgresql://postgres:5432/eddie` |
| `HIVEMQ_DB_USERNAME` | `emqx` |
| `HIVEMQ_DB_PASSWORD` | Required |
| `HIVEMQ_DB_POOL_MAX_SIZE` | `4` |
| `HIVEMQ_DB_POOL_MIN_IDLE` | `0` |
| `HIVEMQ_DB_CONNECTION_TIMEOUT_MS` | `3000` |
| `HIVEMQ_DB_VALIDATION_TIMEOUT_MS` | `2000` |
| `HIVEMQ_DB_IDLE_TIMEOUT_MS` | `600000` |
| `HIVEMQ_DB_MAX_LIFETIME_MS` | `1800000` |
| `HIVEMQ_DB_QUERY_TIMEOUT_SECONDS` | `3` |

### Queries and caching

| Environment variable | Default |
| --- | --- |
| `HIVEMQ_PASSWORD_QUERY` | Password query shown above |
| `HIVEMQ_SUPERUSER_QUERY` | Superuser query shown above |
| `HIVEMQ_ACL_QUERY` | ACL query shown above |
| `HIVEMQ_PUBLISH_ACTION` | `PUBLISH` |
| `HIVEMQ_SUBSCRIBE_ACTION` | `SUBSCRIBE` |
| `HIVEMQ_CACHE_ENABLED` | `true` |
| `HIVEMQ_AUTH_CACHE_SECONDS` | `300` |
| `HIVEMQ_ACL_CACHE_SECONDS` | `300` |
| `HIVEMQ_AUTH_CACHE_JITTER_SECONDS` | `15` |
| `HIVEMQ_ACL_CACHE_JITTER_SECONDS` | `15` |
| `HIVEMQ_CACHE_MAXIMUM_ENTRIES` | `10000` |

The password-hash and authorization caches are independent. Expiry is the configured TTL plus a uniformly distributed value from zero through the configured jitter. ACL cache hits are evaluated directly in the callback; cache misses and every lookup with caching disabled use HiveMQ's managed extension executor so database I/O never blocks an event-loop thread. Disabled caching performs every lookup against PostgreSQL. Caches start empty on every broker start.

### Local user and callback limits

| Environment variable | Default |
| --- | --- |
| `HIVEMQ_LOCAL_SUPERUSER_ENABLED` | `true` |
| `HIVEMQ_LOCAL_SUPERUSER_USERNAME` | `eddie` |
| `AIIDA_MQTT_PASSWORD` | Required when the local user is enabled |
| `HIVEMQ_AUTH_CALLBACK_TIMEOUT_MS` | `5000` |
| `HIVEMQ_MAXIMUM_USERNAME_BYTES` | `1024` |
| `HIVEMQ_MAXIMUM_PASSWORD_BYTES` | `4096` |

### Broker and TLS settings in the image

| Environment variable | Default |
| --- | --- |
| `HIVEMQ_MAX_CONNECTIONS` | `-1` (unlimited) |
| `HIVEMQ_MAX_QUEUED_MESSAGES` | `200000` |
| `HIVEMQ_TLS_ENABLED` | `false` |
| `HIVEMQ_TLS_CERT_FILE` | `/etc/mqtt-tls/tls.crt` |
| `HIVEMQ_TLS_KEY_FILE` | `/etc/mqtt-tls/tls.key` |
| `HIVEMQ_TLS_KEYSTORE_PASSWORD` | Randomly generated at each start |

When TLS is enabled, the image converts the mounted PEM certificate and key to a private PKCS#12 keystore in `/opt/hivemq/data` before starting HiveMQ. The unencrypted listener on port 1883 remains available. Set a fixed keystore password only if an operational requirement calls for it; otherwise leave it unset.

HiveMQ persists broker data under `/opt/hivemq/data`.
