package at.flexidata.eddie.mqtt.auth.security;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class TopicAccessMatcherTest {

    @Test
    void matchesPublishTopicsUsingMqttWildcards() {
        assertTrue(TopicAccessMatcher.matchesPublish("sensors/+/temperature", "sensors/kitchen/temperature"));
        assertTrue(TopicAccessMatcher.matchesPublish("sensors/#", "sensors"));
        assertTrue(TopicAccessMatcher.matchesPublish("sensors/#", "sensors/kitchen/temperature"));
        assertTrue(TopicAccessMatcher.matchesPublish("/+/status", "/device/status"));
        assertFalse(TopicAccessMatcher.matchesPublish("sensors/+/temperature", "sensors/temperature"));
        assertFalse(TopicAccessMatcher.matchesPublish("sensors/kitchen", "sensors/living-room"));
    }

    @Test
    void appliesSystemTopicWildcardRule() {
        assertFalse(TopicAccessMatcher.matchesPublish("#", "$SYS/broker/uptime"));
        assertFalse(TopicAccessMatcher.matchesPublish("+/broker/#", "$SYS/broker/uptime"));
        assertTrue(TopicAccessMatcher.matchesPublish("$SYS/#", "$SYS/broker/uptime"));
    }

    @Test
    void rejectsInvalidPublishInput() {
        assertFalse(TopicAccessMatcher.matchesPublish("broken/#/filter", "broken/topic"));
        assertFalse(TopicAccessMatcher.matchesPublish("prefix+", "prefix-value"));
        assertFalse(TopicAccessMatcher.matchesPublish("#", "topic/+"));
        assertFalse(TopicAccessMatcher.matchesPublish("#", "topic/#"));
        assertFalse(TopicAccessMatcher.matchesPublish("#", "topic\u0000name"));
        assertFalse(TopicAccessMatcher.matchesPublish("", "topic"));
        assertFalse(TopicAccessMatcher.matchesPublish(null, "topic"));
        assertFalse(TopicAccessMatcher.matchesPublish("#", null));
        assertFalse(TopicAccessMatcher.matchesPublish("#", ""));
    }

    @Test
    void allowsOnlySubscriptionsContainedByAclFilter() {
        assertTrue(TopicAccessMatcher.coversSubscription("sensors/#", "sensors/+/temperature"));
        assertTrue(TopicAccessMatcher.coversSubscription("sensors/#", "sensors"));
        assertTrue(TopicAccessMatcher.coversSubscription("sensors/+/#", "sensors/kitchen/#"));
        assertTrue(TopicAccessMatcher.coversSubscription("#", "+/status"));
        assertFalse(TopicAccessMatcher.coversSubscription("sensors/+", "sensors/#"));
        assertFalse(TopicAccessMatcher.coversSubscription("sensors/kitchen/#", "sensors/+/temperature"));
        assertFalse(TopicAccessMatcher.coversSubscription("sensors", "sensors/+"));
        assertFalse(TopicAccessMatcher.coversSubscription("sensors", "sensors/kitchen"));
        assertFalse(TopicAccessMatcher.coversSubscription("sensors/kitchen", "events/kitchen"));
        assertFalse(TopicAccessMatcher.coversSubscription(null, "sensors/#"));
        assertFalse(TopicAccessMatcher.coversSubscription("sensors/#", "broken/+suffix"));
    }

    @Test
    void unwrapsSharedSubscriptionsBeforeCheckingCoverage() {
        assertTrue(TopicAccessMatcher.coversSubscription("sensors/#", "$share/workers/sensors/+/temperature"));
        assertFalse(TopicAccessMatcher.coversSubscription("sensors/#", "$share//sensors/#"));
        assertFalse(TopicAccessMatcher.coversSubscription("sensors/#", "$share/workers"));
    }

    @Test
    void appliesSystemRuleToSubscriptionContainment() {
        assertFalse(TopicAccessMatcher.coversSubscription("#", "$SYS/#"));
        assertTrue(TopicAccessMatcher.coversSubscription("$SYS/#", "$SYS/broker/+"));
        assertTrue(TopicAccessMatcher.coversSubscription("#", "+/#"));
    }
}
