package at.flexidata.eddie.mqtt.auth.config;

import com.hivemq.extension.sdk.api.annotations.NotNull;
import java.time.Duration;
import java.util.Objects;

/**
 * Complete validated runtime configuration for the authentication extension.
 *
 * @param database PostgreSQL connection-pool settings
 * @param queries operator-controlled SQL templates and action names
 * @param cache authentication and authorization cache settings
 * @param localSuperuser optional broker-local recovery user
 * @param callbackTimeout maximum duration of an asynchronous HiveMQ security callback
 * @param maximumUsernameBytes maximum accepted UTF-8 username length
 * @param maximumPasswordBytes maximum accepted password length
 */
public record ExtensionConfig(
        Database database,
        Queries queries,
        Cache cache,
        LocalSuperuser localSuperuser,
        Duration callbackTimeout,
        int maximumUsernameBytes,
        int maximumPasswordBytes) {

    /** Validates the complete configuration. */
    public ExtensionConfig {
        Objects.requireNonNull(database, "database");
        Objects.requireNonNull(queries, "queries");
        Objects.requireNonNull(cache, "cache");
        Objects.requireNonNull(localSuperuser, "localSuperuser");
        requirePositive(callbackTimeout, "callbackTimeout");
        requirePositive(maximumUsernameBytes, "maximumUsernameBytes");
        requirePositive(maximumPasswordBytes, "maximumPasswordBytes");
    }

    /**
     * PostgreSQL connection and HikariCP pool settings.
     *
     * @param url PostgreSQL JDBC URL
     * @param username database role
     * @param password database password; redacted from {@link #toString()}
     * @param maximumPoolSize maximum number of pooled connections
     * @param minimumIdle minimum number of idle connections
     * @param connectionTimeout maximum wait for a pooled connection
     * @param validationTimeout maximum connection-validation duration
     * @param idleTimeout duration after which an idle connection may be retired
     * @param maxLifetime maximum lifetime of a pooled connection
     * @param queryTimeoutSeconds JDBC query timeout in seconds
     */
    public record Database(
            String url,
            String username,
            String password,
            int maximumPoolSize,
            int minimumIdle,
            Duration connectionTimeout,
            Duration validationTimeout,
            Duration idleTimeout,
            Duration maxLifetime,
            int queryTimeoutSeconds) {

        /** Validates the database and pool settings. */
        public Database {
            requireText(url, "db.url");
            if (!url.startsWith("jdbc:postgresql:")) {
                throw new IllegalArgumentException("db.url must be a PostgreSQL JDBC URL");
            }
            requireText(username, "db.username");
            requireText(password, "db.password");
            requirePositive(maximumPoolSize, "db.pool.maximum-size");
            if (minimumIdle < 0 || minimumIdle > maximumPoolSize) {
                throw new IllegalArgumentException(
                        "db.pool.minimum-idle must be between zero and db.pool.maximum-size");
            }
            requirePositive(connectionTimeout, "db.connection-timeout-ms");
            requirePositive(validationTimeout, "db.validation-timeout-ms");
            requireNonNegative(idleTimeout, "db.idle-timeout-ms");
            requirePositive(maxLifetime, "db.max-lifetime-ms");
            requirePositive(queryTimeoutSeconds, "db.query-timeout-seconds");
        }

        /** Returns a diagnostic representation with the database password redacted. */
        @Override
        @NotNull
        public String toString() {
            return "Database[url=" + url
                    + ", username=" + username
                    + ", password=<redacted>, maximumPoolSize=" + maximumPoolSize
                    + ", minimumIdle=" + minimumIdle
                    + ", connectionTimeout=" + connectionTimeout
                    + ", validationTimeout=" + validationTimeout
                    + ", idleTimeout=" + idleTimeout
                    + ", maxLifetime=" + maxLifetime
                    + ", queryTimeoutSeconds=" + queryTimeoutSeconds + ']';
        }
    }

    /**
     * SQL templates and database action values.
     *
     * @param password query taking a username and returning a password hash
     * @param superuser query taking a username and returning a boolean-like value
     * @param acl query taking a username and action and returning topic filters
     * @param publishAction action value used for publish lookups
     * @param subscribeAction action value used for subscribe lookups
     */
    public record Queries(
            String password,
            String superuser,
            String acl,
            String publishAction,
            String subscribeAction) {

        /** Validates every SQL template and action name. */
        public Queries {
            requireText(password, "query.password");
            requireText(superuser, "query.superuser");
            requireText(acl, "query.acl");
            requireText(publishAction, "query.publish-action");
            requireText(subscribeAction, "query.subscribe-action");
        }
    }

    /**
     * Bounded cache configuration.
     *
     * @param enabled whether lookups are cached
     * @param authenticationTtl base lifetime of password-hash entries
     * @param authorizationTtl base lifetime of authorization-rule entries
     * @param authenticationJitter maximum random addition to the authentication lifetime
     * @param authorizationJitter maximum random addition to the authorization lifetime
     * @param maximumEntries maximum entries in each independent cache
     */
    public record Cache(
            boolean enabled,
            Duration authenticationTtl,
            Duration authorizationTtl,
            Duration authenticationJitter,
            Duration authorizationJitter,
            long maximumEntries) {

        /** Validates cache durations and capacity. */
        public Cache {
            requirePositive(authenticationTtl, "cache.authentication-ttl-seconds");
            requirePositive(authorizationTtl, "cache.authorization-ttl-seconds");
            requireNonNegative(authenticationJitter, "cache.authentication-jitter-seconds");
            requireNonNegative(authorizationJitter, "cache.authorization-jitter-seconds");
            if (maximumEntries <= 0) {
                throw new IllegalArgumentException("cache.maximum-entries must be greater than zero");
            }
        }
    }

    /**
     * Optional broker-local superuser credentials.
     *
     * @param enabled whether the local account can authenticate
     * @param username reserved local username
     * @param password local password; redacted from {@link #toString()}
     */
    public record LocalSuperuser(boolean enabled, String username, String password) {

        /** Normalizes disabled credentials and validates enabled credentials. */
        public LocalSuperuser {
            username = Objects.requireNonNullElse(username, "");
            password = Objects.requireNonNullElse(password, "");
            if (enabled) {
                requireText(username, "local-superuser.username");
                requireText(password, "local-superuser.password");
            }
        }

        /** Returns a diagnostic representation with the local password redacted. */
        @Override
        @NotNull
        public String toString() {
            return "LocalSuperuser[enabled=" + enabled + ", username=" + username + ", password=<redacted>]";
        }
    }

    private static void requireText(final String value, final String property) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(property + " must not be blank");
        }
    }

    private static void requirePositive(final int value, final String property) {
        if (value <= 0) {
            throw new IllegalArgumentException(property + " must be greater than zero");
        }
    }

    private static void requirePositive(final Duration value, final String property) {
        Objects.requireNonNull(value, property);
        if (value.isZero() || value.isNegative()) {
            throw new IllegalArgumentException(property + " must be greater than zero");
        }
    }

    private static void requireNonNegative(final Duration value, final String property) {
        Objects.requireNonNull(value, property);
        if (value.isNegative()) {
            throw new IllegalArgumentException(property + " must not be negative");
        }
    }
}
