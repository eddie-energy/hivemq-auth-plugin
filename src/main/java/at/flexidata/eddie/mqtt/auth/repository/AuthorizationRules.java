package at.flexidata.eddie.mqtt.auth.repository;

import java.util.List;

/**
 * Immutable result of an authorization lookup.
 *
 * @param superuser whether all topic operations are allowed
 * @param topicFilters allowed MQTT topic filters when {@code superuser} is false
 */
public record AuthorizationRules(boolean superuser, List<String> topicFilters) {

    /** Defensively copies the supplied topic filters. */
    public AuthorizationRules {
        topicFilters = List.copyOf(topicFilters);
    }

    /**
     * Creates an unrestricted rule set.
     *
     * @return an unrestricted superuser rule set
     */
    public static AuthorizationRules superuserRules() {
        return new AuthorizationRules(true, List.of());
    }
}
