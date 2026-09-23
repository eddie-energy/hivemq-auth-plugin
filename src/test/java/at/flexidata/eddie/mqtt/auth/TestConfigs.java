package at.flexidata.eddie.mqtt.auth;

import at.flexidata.eddie.mqtt.auth.config.ExtensionConfig;
import java.time.Duration;

public final class TestConfigs {

    private TestConfigs() {}

    public static ExtensionConfig config(
            final boolean cacheEnabled, final boolean localEnabled, final int maximumCredentialBytes) {
        return new ExtensionConfig(
                database("jdbc:postgresql://localhost:5432/eddie", "postgres", "postgres"),
                queries(),
                new ExtensionConfig.Cache(
                        cacheEnabled,
                        Duration.ofMinutes(5),
                        Duration.ofMinutes(5),
                        Duration.ZERO,
                        Duration.ZERO,
                        100),
                new ExtensionConfig.LocalSuperuser(localEnabled, "eddie", localEnabled ? "local-secret" : ""),
                Duration.ofSeconds(5),
                maximumCredentialBytes,
                maximumCredentialBytes);
    }

    public static ExtensionConfig.Database database(
            final String jdbcUrl, final String username, final String password) {
        return new ExtensionConfig.Database(
                jdbcUrl,
                username,
                password,
                3,
                0,
                Duration.ofSeconds(3),
                Duration.ofSeconds(2),
                Duration.ofMinutes(10),
                Duration.ofMinutes(30),
                3);
    }

    public static ExtensionConfig.Queries queries() {
        return new ExtensionConfig.Queries(
                "SELECT password_hash FROM aiida.aiida_mqtt_user WHERE username = ? LIMIT 1",
                "SELECT count(*) FROM aiida.aiida_mqtt_user WHERE username = ? AND is_superuser = true",
                "SELECT topic FROM aiida.aiida_mqtt_acl "
                        + "WHERE username = ? AND acl_type = 'ALLOW' AND action = ?",
                "PUBLISH",
                "SUBSCRIBE");
    }
}
