package at.flexidata.eddie.mqtt.auth.repository;

import at.flexidata.eddie.mqtt.auth.security.MqttActivity;
import java.util.Optional;

/** Persistence boundary for password hashes and authorization rules. */
public interface AuthRepository extends AutoCloseable {

    /**
     * Looks up an encoded password.
     *
     * @param username MQTT username
     * @return the non-blank encoded password, or an empty result for an unknown user
     * @throws RepositoryException when the backing store cannot complete the lookup
     */
    Optional<String> findPasswordHash(String username);

    /**
     * Loads the superuser flag and allowed topic filters for an operation.
     *
     * @param username MQTT username
     * @param activity operation for which rules are requested
     * @return immutable authorization rules; unknown users have an empty rule set
     * @throws RepositoryException when the backing store cannot complete the lookup
     */
    AuthorizationRules findAuthorization(String username, MqttActivity activity);

    /** Releases repository resources. */
    @Override
    void close();
}
