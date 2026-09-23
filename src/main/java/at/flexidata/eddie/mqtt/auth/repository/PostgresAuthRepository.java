package at.flexidata.eddie.mqtt.auth.repository;

import at.flexidata.eddie.mqtt.auth.config.ExtensionConfig;
import at.flexidata.eddie.mqtt.auth.security.MqttActivity;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

/** PostgreSQL implementation of {@link AuthRepository} backed by a bounded HikariCP pool. */
public final class PostgresAuthRepository implements AuthRepository {

    private static final String APPLICATION_NAME = "eddie-mqtt-auth-hivemq";

    private final HikariDataSource dataSource;
    private final ExtensionConfig.Queries queries;
    private final int queryTimeoutSeconds;

    /**
     * Creates a repository from validated database and SQL-template settings.
     *
     * <p>The SQL templates are trusted operator configuration. All request-controlled values are
     * bound through JDBC parameters.
     *
     * @param database connection-pool settings
     * @param queries SQL templates and action values
     */
    public PostgresAuthRepository(final ExtensionConfig.Database database, final ExtensionConfig.Queries queries) {
        this(createDataSource(database), queries, database.queryTimeoutSeconds());
    }

    PostgresAuthRepository(
            final HikariDataSource dataSource,
            final ExtensionConfig.Queries queries,
            final int queryTimeoutSeconds) {
        this.dataSource = dataSource;
        this.queries = queries;
        this.queryTimeoutSeconds = queryTimeoutSeconds;
    }

    /** {@inheritDoc} */
    @Override
    @SuppressWarnings("java:S2077") // The SQL template is trusted configuration; the username is always bound.
    @SuppressFBWarnings(
            value = "SQL_PREPARED_STATEMENT_GENERATED_FROM_NONCONSTANT_STRING",
            justification = "The SQL template is trusted configuration; the username is always bound.")
    public Optional<String> findPasswordHash(final String username) {
        try (Connection connection = dataSource.getConnection();
                PreparedStatement statement = connection.prepareStatement(queries.password())) {
            statement.setQueryTimeout(queryTimeoutSeconds);
            statement.setString(1, username);
            try (ResultSet resultSet = statement.executeQuery()) {
                if (!resultSet.next()) {
                    return Optional.empty();
                }
                return Optional.ofNullable(resultSet.getString(1)).filter(value -> !value.isBlank());
            }
        } catch (SQLException exception) {
            throw new RepositoryException("PostgreSQL password lookup failed", exception);
        }
    }

    /** {@inheritDoc} */
    @Override
    public AuthorizationRules findAuthorization(final String username, final MqttActivity activity) {
        try (Connection connection = dataSource.getConnection()) {
            if (isSuperuser(connection, username)) {
                return AuthorizationRules.superuserRules();
            }
            return new AuthorizationRules(false, findTopicFilters(connection, username, actionName(activity)));
        } catch (SQLException exception) {
            throw new RepositoryException("PostgreSQL authorization lookup failed", exception);
        }
    }

    /** {@inheritDoc} */
    @Override
    public void close() {
        dataSource.close();
    }

    @SuppressWarnings("java:S2077") // The SQL template is trusted configuration; the username is always bound.
    @SuppressFBWarnings(
            value = "SQL_PREPARED_STATEMENT_GENERATED_FROM_NONCONSTANT_STRING",
            justification = "The SQL template is trusted configuration; the username is always bound.")
    private boolean isSuperuser(final Connection connection, final String username) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(queries.superuser())) {
            statement.setQueryTimeout(queryTimeoutSeconds);
            statement.setString(1, username);
            try (ResultSet resultSet = statement.executeQuery()) {
                return resultSet.next() && asBoolean(resultSet.getObject(1));
            }
        }
    }

    @SuppressWarnings("java:S2077") // The SQL template is trusted configuration; all request data is always bound.
    @SuppressFBWarnings(
            value = "SQL_PREPARED_STATEMENT_GENERATED_FROM_NONCONSTANT_STRING",
            justification = "The SQL template is trusted configuration; all request data is always bound.")
    private List<String> findTopicFilters(
            final Connection connection, final String username, final String action) throws SQLException {
        final Set<String> filters = new LinkedHashSet<>();
        try (PreparedStatement statement = connection.prepareStatement(queries.acl())) {
            statement.setQueryTimeout(queryTimeoutSeconds);
            statement.setString(1, username);
            statement.setString(2, action);
            try (ResultSet resultSet = statement.executeQuery()) {
                while (resultSet.next()) {
                    final String topicFilter = resultSet.getString(1);
                    if (topicFilter != null && !topicFilter.isBlank()) {
                        filters.add(topicFilter);
                    }
                }
            }
        }
        return new ArrayList<>(filters);
    }

    private String actionName(final MqttActivity activity) {
        return switch (activity) {
            case PUBLISH -> queries.publishAction();
            case SUBSCRIBE -> queries.subscribeAction();
        };
    }

    static boolean asBoolean(final Object value) {
        if (value instanceof Boolean bool) {
            return bool;
        }
        if (value instanceof Number number) {
            return number.longValue() != 0;
        }
        if (value instanceof String text) {
            return switch (text.trim().toLowerCase(Locale.ROOT)) {
                case "1", "t", "true", "y", "yes" -> true;
                default -> false;
            };
        }
        return false;
    }

    private static HikariDataSource createDataSource(final ExtensionConfig.Database database) {
        final HikariConfig hikari = new HikariConfig();
        hikari.setPoolName(APPLICATION_NAME);
        hikari.setJdbcUrl(database.url());
        hikari.setUsername(database.username());
        hikari.setPassword(database.password());
        hikari.setMaximumPoolSize(database.maximumPoolSize());
        hikari.setMinimumIdle(database.minimumIdle());
        hikari.setConnectionTimeout(database.connectionTimeout().toMillis());
        hikari.setValidationTimeout(database.validationTimeout().toMillis());
        hikari.setIdleTimeout(database.idleTimeout().toMillis());
        hikari.setMaxLifetime(database.maxLifetime().toMillis());
        hikari.setInitializationFailTimeout(-1);
        hikari.addDataSourceProperty("ApplicationName", APPLICATION_NAME);
        return new HikariDataSource(hikari);
    }
}
