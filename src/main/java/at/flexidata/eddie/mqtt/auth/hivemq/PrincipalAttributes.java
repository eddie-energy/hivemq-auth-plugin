package at.flexidata.eddie.mqtt.auth.hivemq;

import at.flexidata.eddie.mqtt.auth.security.AuthenticatedPrincipal;
import com.hivemq.extension.sdk.api.client.parameter.ConnectionAttributeStore;
import java.util.Optional;

final class PrincipalAttributes {

    private static final String USERNAME = "eddie.mqtt.auth.username";
    private static final String LOCAL_SUPERUSER = "eddie.mqtt.auth.local-superuser";

    private PrincipalAttributes() {}

    static void put(final ConnectionAttributeStore attributes, final AuthenticatedPrincipal principal) {
        attributes.putAsString(USERNAME, principal.username());
        attributes.putAsString(LOCAL_SUPERUSER, Boolean.toString(principal.localSuperuser()));
    }

    static Optional<AuthenticatedPrincipal> get(final ConnectionAttributeStore attributes) {
        return attributes.getAsString(USERNAME).map(username -> new AuthenticatedPrincipal(
                username,
                attributes.getAsString(LOCAL_SUPERUSER).map(Boolean::parseBoolean).orElse(false)));
    }
}
