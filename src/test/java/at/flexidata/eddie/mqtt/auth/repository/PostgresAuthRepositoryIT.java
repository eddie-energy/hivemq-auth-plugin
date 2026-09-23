package at.flexidata.eddie.mqtt.auth.repository;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import at.flexidata.eddie.mqtt.auth.TestConfigs;
import at.flexidata.eddie.mqtt.auth.config.ExtensionConfig;
import at.flexidata.eddie.mqtt.auth.security.MqttActivity;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Optional;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers
class PostgresAuthRepositoryIT {

    @SuppressWarnings("resource") // The JUnit Testcontainers extension owns the static container lifecycle.
    @Container
    private static final PostgreSQLContainer<?> POSTGRES =
            new PostgreSQLContainer<>("postgres:17-alpine").withDatabaseName("eddie");

    private PostgresAuthRepository repository;

    @BeforeAll
    static void createSchema() throws SQLException {
        try (Connection connection = connection(); Statement statement = connection.createStatement()) {
            statement.execute("CREATE SCHEMA aiida");
            statement.execute("""
                    CREATE TABLE aiida.aiida_mqtt_user (
                        username text PRIMARY KEY,
                        password_hash text NOT NULL,
                        is_superuser boolean NOT NULL DEFAULT false
                    )
                    """);
            statement.execute("""
                    CREATE TABLE aiida.aiida_mqtt_acl (
                        username text NOT NULL,
                        action text NOT NULL,
                        acl_type text NOT NULL,
                        topic text
                    )
                    """);
        }
    }

    @BeforeEach
    void createRepositoryAndRows() throws SQLException {
        try (Connection connection = connection(); Statement statement = connection.createStatement()) {
            statement.execute("TRUNCATE aiida.aiida_mqtt_user, aiida.aiida_mqtt_acl");
            statement.execute("""
                    INSERT INTO aiida.aiida_mqtt_user (username, password_hash, is_superuser) VALUES
                        ('alice', '$2a$10$alice', false),
                        ('admin', '$2a$10$admin', true)
                    """);
            statement.execute("""
                    INSERT INTO aiida.aiida_mqtt_acl (username, action, acl_type, topic) VALUES
                        ('alice', 'PUBLISH', 'ALLOW', 'sensors/#'),
                        ('alice', 'PUBLISH', 'ALLOW', 'sensors/#'),
                        ('alice', 'PUBLISH', 'DENY', 'sensors/private/#'),
                        ('alice', 'SUBSCRIBE', 'ALLOW', 'events/+/status'),
                        ('alice', 'SUBSCRIBE', 'ALLOW', NULL)
                    """);
        }
        final ExtensionConfig.Database database =
                TestConfigs.database(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        repository = new PostgresAuthRepository(database, TestConfigs.queries());
    }

    @AfterEach
    void closeRepository() {
        repository.close();
    }

    @Test
    void looksUpPasswordHashWithPreparedQuery() {
        assertEquals(Optional.of("$2a$10$alice"), repository.findPasswordHash("alice"));
        assertEquals(Optional.empty(), repository.findPasswordHash("missing"));
        assertEquals(Optional.empty(), repository.findPasswordHash("alice' OR true --"));
    }

    @Test
    void loadsAllowedAclTopicsForRequestedAction() {
        final AuthorizationRules publish = repository.findAuthorization("alice", MqttActivity.PUBLISH);
        final AuthorizationRules subscribe = repository.findAuthorization("alice", MqttActivity.SUBSCRIBE);

        assertFalse(publish.superuser());
        assertEquals(1, publish.topicFilters().size());
        assertEquals("sensors/#", publish.topicFilters().getFirst());
        assertEquals(1, subscribe.topicFilters().size());
        assertEquals("events/+/status", subscribe.topicFilters().getFirst());
    }

    @Test
    void detectsDatabaseSuperuserAndDeniesUnknownUserByDefault() {
        assertTrue(repository.findAuthorization("admin", MqttActivity.PUBLISH).superuser());
        final AuthorizationRules missing = repository.findAuthorization("missing", MqttActivity.SUBSCRIBE);
        assertFalse(missing.superuser());
        assertTrue(missing.topicFilters().isEmpty());
    }

    @Test
    void wrapsDatabaseFailuresWithoutLeakingCredentials() {
        repository.close();

        final RepositoryException passwordException =
                assertThrows(RepositoryException.class, () -> repository.findPasswordHash("alice"));
        final RepositoryException authorizationException = assertThrows(
                RepositoryException.class,
                () -> repository.findAuthorization("alice", MqttActivity.PUBLISH));

        assertTrue(passwordException.getMessage().contains("password lookup"));
        assertTrue(authorizationException.getMessage().contains("authorization lookup"));
        assertFalse(passwordException.getMessage().contains(POSTGRES.getPassword()));
        assertFalse(authorizationException.getMessage().contains(POSTGRES.getPassword()));
    }

    private static Connection connection() throws SQLException {
        return DriverManager.getConnection(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
    }
}
