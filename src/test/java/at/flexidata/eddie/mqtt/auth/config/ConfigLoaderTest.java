package at.flexidata.eddie.mqtt.auth.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ConfigLoaderTest {

    @TempDir
    Path temporaryDirectory;

    @Test
    void loadsConfigurationAndResolvesEnvironment() throws IOException {
        final Path configFile = writeConfiguration("${DB_PASSWORD}", "true", "true");

        final ExtensionConfig config = ConfigLoader.load(configFile, Map.of("DB_PASSWORD", "p$a\\ss")::get);

        assertEquals("p$a\\ss", config.database().password());
        assertEquals("jdbc:postgresql://db:5432/eddie", config.database().url());
        assertEquals(4, config.database().maximumPoolSize());
        assertTrue(config.cache().enabled());
        assertTrue(config.localSuperuser().enabled());
        assertEquals("eddie", config.localSuperuser().username());
        assertEquals(1024, config.maximumUsernameBytes());
    }

    @Test
    void usesPlaceholderDefaultAndAllowsDisabledLocalUserWithoutPassword() throws IOException {
        final Path configFile = writeConfiguration("${DB_PASSWORD:fallback}", "false", "false");

        final ExtensionConfig config = ConfigLoader.load(configFile, ignored -> null);

        assertEquals("fallback", config.database().password());
        assertFalse(config.cache().enabled());
        assertFalse(config.localSuperuser().enabled());
        assertEquals("", config.localSuperuser().password());
    }

    @Test
    void rejectsMissingRequiredEnvironmentVariable() throws IOException {
        final Path configFile = writeConfiguration("${DB_PASSWORD}", "true", "true");

        final IllegalArgumentException exception =
                assertThrows(IllegalArgumentException.class, () -> ConfigLoader.load(configFile, ignored -> null));

        assertTrue(exception.getMessage().contains("DB_PASSWORD"));
    }

    @Test
    void rejectsInvalidBooleanAndNumber() throws IOException {
        final Path invalidBoolean = writeConfiguration("password", "sometimes", "true");
        assertThrows(IllegalArgumentException.class, () -> ConfigLoader.load(invalidBoolean, ignored -> null));

        final String invalidNumberText = baseConfiguration("password", "true", "true")
                .replace("db.pool.maximum-size=4", "db.pool.maximum-size=many");
        final Path invalidNumber = temporaryDirectory.resolve("invalid-number.properties");
        Files.writeString(invalidNumber, invalidNumberText);
        assertThrows(IllegalArgumentException.class, () -> ConfigLoader.load(invalidNumber, ignored -> null));
    }

    @Test
    void rejectsMissingProperty() throws IOException {
        final Path configFile = temporaryDirectory.resolve("missing.properties");
        Files.writeString(configFile, "db.url=jdbc:postgresql://db/eddie\n");

        assertThrows(IllegalArgumentException.class, () -> ConfigLoader.load(configFile, ignored -> null));
    }

    @Test
    void resolvePreservesReplacementMetacharacters() {
        assertEquals(
                "before-$value\\after",
                ConfigLoader.resolve("before-${VALUE}", key -> key.equals("VALUE") ? "$value\\after" : null));
    }

    private Path writeConfiguration(
            final String databasePassword, final String cacheEnabled, final String localEnabled)
            throws IOException {
        final Path configFile = temporaryDirectory.resolve("extension-" + cacheEnabled + '-' + localEnabled + ".properties");
        Files.writeString(configFile, baseConfiguration(databasePassword, cacheEnabled, localEnabled));
        return configFile;
    }

    private static String baseConfiguration(
            final String databasePassword, final String cacheEnabled, final String localEnabled) {
        return """
                db.url=jdbc:postgresql://db:5432/eddie
                db.username=emqx
                db.password=%s
                db.pool.maximum-size=4
                db.pool.minimum-idle=0
                db.connection-timeout-ms=3000
                db.validation-timeout-ms=2000
                db.idle-timeout-ms=600000
                db.max-lifetime-ms=1800000
                db.query-timeout-seconds=3
                query.password=SELECT password_hash FROM users WHERE username = ?
                query.superuser=SELECT count(*) FROM users WHERE username = ?
                query.acl=SELECT topic FROM acl WHERE username = ? AND action = ?
                query.publish-action=PUBLISH
                query.subscribe-action=SUBSCRIBE
                cache.enabled=%s
                cache.authentication-ttl-seconds=300
                cache.authorization-ttl-seconds=300
                cache.authentication-jitter-seconds=0
                cache.authorization-jitter-seconds=0
                cache.maximum-entries=10000
                local-superuser.enabled=%s
                local-superuser.username=eddie
                local-superuser.password=%s
                callback.timeout-ms=5000
                security.maximum-username-bytes=1024
                security.maximum-password-bytes=4096
                """.formatted(
                databasePassword,
                cacheEnabled,
                localEnabled,
                Boolean.parseBoolean(localEnabled) ? "local-secret" : "");
    }
}
