package at.flexidata.eddie.mqtt.auth.security;

/** Verifies an MQTT password against an encoded password obtained from the repository. */
@FunctionalInterface
public interface PasswordVerifier {

    /**
     * Verifies a password without converting the request bytes to an immutable string.
     *
     * @param password password bytes supplied by the MQTT client
     * @param encodedPassword encoded password from the trusted repository
     * @return {@code true} when the password matches
     */
    boolean matches(byte[] password, String encodedPassword);
}
