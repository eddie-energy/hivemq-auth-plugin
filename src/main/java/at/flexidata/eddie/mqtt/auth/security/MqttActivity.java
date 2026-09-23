package at.flexidata.eddie.mqtt.auth.security;

/** MQTT operations for which topic authorization rules are loaded. */
public enum MqttActivity {
    /** Publishing a message to a concrete topic name. */
    PUBLISH,
    /** Creating a subscription or delivering a message to an existing subscription. */
    SUBSCRIBE
}
