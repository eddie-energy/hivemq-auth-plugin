package at.flexidata.eddie.mqtt.auth.security;

/**
 * Implements MQTT topic-filter matching and safe subscription containment for ACL checks.
 *
 * <p>The matcher applies the MQTT system-topic rule: a filter beginning with {@code #} or
 * {@code +} does not match a topic beginning with {@code $}. Shared subscriptions are unwrapped
 * before their requested filter is evaluated.
 */
public final class TopicAccessMatcher {

    private static final String MULTI_LEVEL_WILDCARD = "#";
    private static final String SINGLE_LEVEL_WILDCARD = "+";
    private static final String SHARED_SUBSCRIPTION_PREFIX = "$share/";

    private TopicAccessMatcher() {}

    /**
     * Tests whether an ACL filter matches a concrete publish topic.
     *
     * @param allowedFilter MQTT topic filter from an ACL row
     * @param topic concrete publish topic
     * @return {@code true} only when both inputs are valid and the filter matches the topic
     */
    public static boolean matchesPublish(final String allowedFilter, final String topic) {
        if (isInvalidFilter(allowedFilter) || !isValidTopicName(topic)) {
            return false;
        }

        final String[] allowedLevels = levels(allowedFilter);
        if (topic.charAt(0) == '$' && isWildcard(allowedLevels[0])) {
            return false;
        }

        final String[] topicLevels = levels(topic);
        int allowedIndex = 0;
        int topicIndex = 0;
        while (allowedIndex < allowedLevels.length && topicIndex < topicLevels.length) {
            final String allowed = allowedLevels[allowedIndex];
            if (MULTI_LEVEL_WILDCARD.equals(allowed)) {
                return true;
            }
            if (!SINGLE_LEVEL_WILDCARD.equals(allowed) && !allowed.equals(topicLevels[topicIndex])) {
                return false;
            }
            allowedIndex++;
            topicIndex++;
        }

        if (allowedIndex == allowedLevels.length && topicIndex == topicLevels.length) {
            return true;
        }
        return topicIndex == topicLevels.length
                && allowedIndex == allowedLevels.length - 1
                && MULTI_LEVEL_WILDCARD.equals(allowedLevels[allowedIndex]);
    }

    /**
     * Tests whether every topic selected by a requested subscription is contained by an ACL
     * filter.
     *
     * @param allowedFilter MQTT topic filter from an ACL row
     * @param requestedFilter client subscription filter, optionally using {@code $share/group/}
     * @return {@code true} only when the requested subscription cannot escape the ACL filter
     */
    public static boolean coversSubscription(final String allowedFilter, final String requestedFilter) {
        final String normalizedRequested = unwrapSharedSubscription(requestedFilter);
        if (isInvalidFilter(allowedFilter) || isInvalidFilter(normalizedRequested)) {
            return false;
        }

        final String[] allowedLevels = levels(allowedFilter);
        final String[] requestedLevels = levels(normalizedRequested);
        if (startsWithDollarLiteral(requestedLevels) && isWildcard(allowedLevels[0])) {
            return false;
        }

        return coversLevels(allowedLevels, requestedLevels);
    }

    private static boolean coversLevels(final String[] allowedLevels, final String[] requestedLevels) {
        int allowedIndex = 0;
        for (String requested : requestedLevels) {
            if (isMultiLevelAt(allowedLevels, allowedIndex)) {
                return true;
            }
            if (MULTI_LEVEL_WILDCARD.equals(requested)) {
                return false;
            }
            if (allowedIndex == allowedLevels.length) {
                return false;
            }
            final String allowed = allowedLevels[allowedIndex];
            if (!SINGLE_LEVEL_WILDCARD.equals(allowed) && !allowed.equals(requested)) {
                return false;
            }
            allowedIndex++;
        }
        return allowedIndex == allowedLevels.length || isMultiLevelAt(allowedLevels, allowedIndex);
    }

    private static boolean isMultiLevelAt(final String[] levels, final int index) {
        return index < levels.length && MULTI_LEVEL_WILDCARD.equals(levels[index]);
    }

    static boolean isInvalidFilter(final String filter) {
        if (filter == null || filter.isEmpty() || filter.indexOf('\u0000') >= 0) {
            return true;
        }
        final String[] filterLevels = levels(filter);
        for (int index = 0; index < filterLevels.length; index++) {
            final String level = filterLevels[index];
            if (level.indexOf('#') >= 0
                    && (!MULTI_LEVEL_WILDCARD.equals(level) || index != filterLevels.length - 1)) {
                return true;
            }
            if (level.indexOf('+') >= 0 && !SINGLE_LEVEL_WILDCARD.equals(level)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isValidTopicName(final String topic) {
        return topic != null
                && !topic.isEmpty()
                && topic.indexOf('\u0000') < 0
                && topic.indexOf('#') < 0
                && topic.indexOf('+') < 0;
    }

    private static String unwrapSharedSubscription(final String filter) {
        if (filter == null || !filter.startsWith(SHARED_SUBSCRIPTION_PREFIX)) {
            return filter;
        }
        final int filterStart = filter.indexOf('/', SHARED_SUBSCRIPTION_PREFIX.length());
        if (filterStart < 0 || filterStart == SHARED_SUBSCRIPTION_PREFIX.length()) {
            return "";
        }
        return filter.substring(filterStart + 1);
    }

    private static boolean startsWithDollarLiteral(final String[] levels) {
        return !isWildcard(levels[0]) && levels[0].startsWith("$");
    }

    private static boolean isWildcard(final String level) {
        return MULTI_LEVEL_WILDCARD.equals(level) || SINGLE_LEVEL_WILDCARD.equals(level);
    }

    private static String[] levels(final String topicOrFilter) {
        return topicOrFilter.split("/", -1);
    }

}
