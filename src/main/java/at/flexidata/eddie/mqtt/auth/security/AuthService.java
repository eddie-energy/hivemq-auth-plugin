package at.flexidata.eddie.mqtt.auth.security;

import at.flexidata.eddie.mqtt.auth.config.ExtensionConfig;
import at.flexidata.eddie.mqtt.auth.repository.AuthRepository;
import at.flexidata.eddie.mqtt.auth.repository.AuthorizationRules;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Arrays;
import java.util.Optional;
import java.util.concurrent.ThreadLocalRandom;
import org.jspecify.annotations.NullMarked;

/**
 * Coordinates credential verification, topic authorization, and the bounded lookup caches.
 *
 * <p>The service owns the supplied repository. Callers must invoke {@link #close()} to invalidate
 * sensitive cache state, clear the local password bytes, and close the database pool.
 */
public final class AuthService implements AutoCloseable {

    private final AuthRepository repository;
    private final PasswordVerifier passwordVerifier;
    private final ExtensionConfig.LocalSuperuser localSuperuser;
    private final byte[] localPassword;
    private final int maximumUsernameBytes;
    private final int maximumPasswordBytes;
    private final boolean cacheEnabled;
    private final Cache<String, PasswordLookup> passwordCache;
    private final Cache<AuthorizationKey, AuthorizationRules> authorizationCache;

    /**
     * Creates an authentication service and its independent password and ACL caches.
     *
     * @param repository repository owned by this service
     * @param passwordVerifier encoded-password verifier
     * @param config validated extension configuration
     */
    public AuthService(
            final AuthRepository repository,
            final PasswordVerifier passwordVerifier,
            final ExtensionConfig config) {
        this.repository = repository;
        this.passwordVerifier = passwordVerifier;
        this.localSuperuser = config.localSuperuser();
        this.localPassword = localSuperuser.password().getBytes(StandardCharsets.UTF_8);
        this.maximumUsernameBytes = config.maximumUsernameBytes();
        this.maximumPasswordBytes = config.maximumPasswordBytes();
        this.cacheEnabled = config.cache().enabled();

        final long maximumCacheSize = config.cache().maximumEntries();
        this.passwordCache = Caffeine.newBuilder()
                .maximumSize(maximumCacheSize)
                .expireAfter(new JitteredExpiry<String, PasswordLookup>(
                        config.cache().authenticationTtl(), config.cache().authenticationJitter()))
                .build();
        this.authorizationCache = Caffeine.newBuilder()
                .maximumSize(maximumCacheSize)
                .expireAfter(new JitteredExpiry<AuthorizationKey, AuthorizationRules>(
                        config.cache().authorizationTtl(), config.cache().authorizationJitter()))
                .build();
    }

    /**
     * Checks request credential sizes before allocating or scheduling authentication work.
     *
     * @param username MQTT username
     * @param passwordBytes remaining password bytes in the CONNECT packet
     * @return {@code true} when both configured limits are satisfied
     */
    public boolean credentialsWithinLimits(final String username, final int passwordBytes) {
        return username.getBytes(StandardCharsets.UTF_8).length <= maximumUsernameBytes
                && passwordBytes <= maximumPasswordBytes;
    }

    /**
     * Authenticates local or database-backed credentials.
     *
     * @param username MQTT username
     * @param password password bytes supplied by the client; ownership remains with the caller
     * @return the authenticated principal, or an empty result when credentials do not match
     */
    public Optional<AuthenticatedPrincipal> authenticate(final String username, final byte[] password) {
        if (!credentialsWithinLimits(username, password.length)) {
            return Optional.empty();
        }

        if (localSuperuser.enabled() && localSuperuser.username().equals(username)) {
            if (MessageDigest.isEqual(localPassword, password)) {
                return Optional.of(new AuthenticatedPrincipal(username, true));
            }
            return Optional.empty();
        }

        final PasswordLookup lookup = cacheEnabled
                ? passwordCache.get(
                        username, key -> new PasswordLookup(repository.findPasswordHash(key).orElse(null)))
                : new PasswordLookup(repository.findPasswordHash(username).orElse(null));
        if (lookup.encodedPassword() == null) {
            return Optional.empty();
        }
        if (!passwordVerifier.matches(password, lookup.encodedPassword())) {
            return Optional.empty();
        }
        return Optional.of(new AuthenticatedPrincipal(username, false));
    }

    /**
     * Loads authorization rules when necessary and evaluates an MQTT operation.
     *
     * @param principal authenticated connection principal
     * @param activity operation being authorized
     * @param topicOrFilter publish topic or requested subscription filter
     * @return {@code true} when the operation is allowed
     */
    public boolean authorize(
            final AuthenticatedPrincipal principal, final MqttActivity activity, final String topicOrFilter) {
        if (principal.localSuperuser()) {
            return true;
        }

        final AuthorizationKey key = new AuthorizationKey(principal.username(), activity);
        final AuthorizationRules rules = cacheEnabled
                ? authorizationCache.get(
                        key, ignored -> repository.findAuthorization(principal.username(), activity))
                : repository.findAuthorization(principal.username(), activity);
        if (rules == null) {
            return false;
        }
        return evaluateAuthorization(rules, activity, topicOrFilter);
    }

    /**
     * Returns a decision without touching PostgreSQL, or an empty result when the caller must use
     * {@link #authorize(AuthenticatedPrincipal, MqttActivity, String)} on a managed executor.
     *
     * @param principal authenticated connection principal
     * @param activity operation being authorized
     * @param topicOrFilter publish topic or requested subscription filter
     * @return a cached decision, or an empty result on a cache miss or when caching is disabled
     */
    public Optional<Boolean> authorizeFromCache(
            final AuthenticatedPrincipal principal, final MqttActivity activity, final String topicOrFilter) {
        if (principal.localSuperuser()) {
            return Optional.of(true);
        }
        if (!cacheEnabled) {
            return Optional.empty();
        }

        final AuthorizationRules rules =
                authorizationCache.getIfPresent(new AuthorizationKey(principal.username(), activity));
        if (rules == null) {
            return Optional.empty();
        }
        return Optional.of(evaluateAuthorization(rules, activity, topicOrFilter));
    }

    private static boolean evaluateAuthorization(
            final AuthorizationRules rules, final MqttActivity activity, final String topicOrFilter) {
        if (rules.superuser()) {
            return true;
        }
        return rules.topicFilters().stream().anyMatch(filter -> switch (activity) {
            case PUBLISH -> TopicAccessMatcher.matchesPublish(filter, topicOrFilter);
            case SUBSCRIBE -> TopicAccessMatcher.coversSubscription(filter, topicOrFilter);
        });
    }

    /** Invalidates all cached password lookups and authorization rules. */
    public void invalidateCaches() {
        passwordCache.invalidateAll();
        authorizationCache.invalidateAll();
    }

    /** Invalidates caches, clears local password bytes, and closes the owned repository. */
    @Override
    public void close() {
        invalidateCaches();
        Arrays.fill(localPassword, (byte) 0);
        repository.close();
    }

    private record PasswordLookup(String encodedPassword) {}

    private record AuthorizationKey(String username, MqttActivity activity) {}

    @NullMarked
    private static final class JitteredExpiry<K, V> implements Expiry<K, V> {

        private final long timeToLiveNanos;
        private final long jitterNanos;

        private JitteredExpiry(final Duration timeToLive, final Duration jitter) {
            timeToLiveNanos = timeToLive.toNanos();
            jitterNanos = jitter.toNanos();
        }

        @Override
        public long expireAfterCreate(final K key, final V value, final long currentTime) {
            return randomizedDuration();
        }

        @Override
        public long expireAfterUpdate(
                final K key, final V value, final long currentTime, final long currentDuration) {
            return randomizedDuration();
        }

        @Override
        public long expireAfterRead(
                final K key, final V value, final long currentTime, final long currentDuration) {
            return currentDuration;
        }

        @SuppressWarnings("java:S2245") // Cache-expiry jitter is not used for a security decision.
        private long randomizedDuration() {
            if (jitterNanos == 0) {
                return timeToLiveNanos;
            }
            final long randomJitter = ThreadLocalRandom.current().nextLong(jitterNanos + 1);
            return Math.addExact(timeToLiveNanos, randomJitter);
        }
    }
}
