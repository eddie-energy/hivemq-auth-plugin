package at.flexidata.eddie.mqtt.auth.config;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import at.flexidata.eddie.mqtt.auth.TestConfigs;
import java.time.Duration;
import org.junit.jupiter.api.Test;

class ExtensionConfigTest {

    private static final Duration ONE_SECOND = Duration.ofSeconds(1);
    private static final Duration NEGATIVE_ONE_SECOND = Duration.ofSeconds(-1);
    private static final Duration ONE_MINUTE = Duration.ofMinutes(1);

    @Test
    void validatesDatabaseSettings() {
        assertThrows(
                IllegalArgumentException.class,
                () -> TestConfigs.database("jdbc:mysql://localhost/eddie", "user", "password"));
        assertThrows(
                IllegalArgumentException.class,
                () -> new ExtensionConfig.Database(
                        "jdbc:postgresql://localhost/eddie",
                        "user",
                        "password",
                        1,
                        2,
                        ONE_SECOND,
                        ONE_SECOND,
                        Duration.ZERO,
                        ONE_MINUTE,
                        1));
    }

    @Test
    void validatesCacheAndLocalSuperuserSettings() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new ExtensionConfig.Cache(
                        true,
                        Duration.ZERO,
                        ONE_SECOND,
                        Duration.ZERO,
                        Duration.ZERO,
                        1));
        assertThrows(
                IllegalArgumentException.class,
                () -> new ExtensionConfig.Cache(
                        true,
                        ONE_SECOND,
                        ONE_SECOND,
                        NEGATIVE_ONE_SECOND,
                        Duration.ZERO,
                        1));
        assertThrows(
                IllegalArgumentException.class,
                () -> new ExtensionConfig.Cache(
                        true,
                        ONE_SECOND,
                        ONE_SECOND,
                        Duration.ZERO,
                        NEGATIVE_ONE_SECOND,
                        1));
        assertThrows(
                IllegalArgumentException.class,
                () -> new ExtensionConfig.Cache(
                        true,
                        ONE_SECOND,
                        ONE_SECOND,
                        Duration.ZERO,
                        Duration.ZERO,
                        0));
        assertThrows(
                IllegalArgumentException.class,
                () -> new ExtensionConfig.LocalSuperuser(true, "eddie", ""));
        assertDoesNotThrow(() -> new ExtensionConfig.LocalSuperuser(false, null, null));
    }

    @Test
    void validatesTopLevelLimits() {
        final ExtensionConfig valid = TestConfigs.config(true, true, 1024);
        final ExtensionConfig.Database database = valid.database();
        final ExtensionConfig.Queries queries = valid.queries();
        final ExtensionConfig.Cache cache = valid.cache();
        final ExtensionConfig.LocalSuperuser localSuperuser = valid.localSuperuser();
        assertThrows(
                IllegalArgumentException.class,
                () -> new ExtensionConfig(
                        database,
                        queries,
                        cache,
                        localSuperuser,
                        Duration.ZERO,
                        1,
                        1));
        assertThrows(
                IllegalArgumentException.class,
                () -> new ExtensionConfig(
                        database,
                        queries,
                        cache,
                        localSuperuser,
                        ONE_SECOND,
                        0,
                        1));
    }

    @Test
    void redactsSecretsFromDiagnosticStrings() {
        final ExtensionConfig baseline = TestConfigs.config(true, true, 1024);
        final ExtensionConfig.Database database =
                TestConfigs.database("jdbc:postgresql://localhost/eddie", "db-user", "database-secret-value");
        final ExtensionConfig.LocalSuperuser localSuperuser =
                new ExtensionConfig.LocalSuperuser(true, "eddie", "local-secret-value");
        final ExtensionConfig config = new ExtensionConfig(
                database,
                baseline.queries(),
                baseline.cache(),
                localSuperuser,
                baseline.callbackTimeout(),
                baseline.maximumUsernameBytes(),
                baseline.maximumPasswordBytes());

        final String diagnostic = config.toString();
        assertFalse(diagnostic.contains("database-secret-value"));
        assertFalse(diagnostic.contains("local-secret-value"));
        assertTrue(diagnostic.contains("password=<redacted>"));
    }
}
