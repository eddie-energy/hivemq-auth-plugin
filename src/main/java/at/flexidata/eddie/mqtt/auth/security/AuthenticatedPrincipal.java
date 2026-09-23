package at.flexidata.eddie.mqtt.auth.security;

import java.util.Objects;

/**
 * Identity stored on an authenticated HiveMQ connection.
 *
 * @param username authenticated MQTT username
 * @param localSuperuser whether this is the configured broker-local superuser
 */
public record AuthenticatedPrincipal(String username, boolean localSuperuser) {

    /** Validates that the username is present. */
    public AuthenticatedPrincipal {
        Objects.requireNonNull(username, "username");
    }
}
