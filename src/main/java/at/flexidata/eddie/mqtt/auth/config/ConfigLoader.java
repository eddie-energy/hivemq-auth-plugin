package at.flexidata.eddie.mqtt.auth.config;

import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Objects;
import java.util.Properties;
import java.util.function.UnaryOperator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Loads and validates an {@link ExtensionConfig} from a UTF-8 Java properties file. */
public final class ConfigLoader {

    private static final Pattern ENVIRONMENT_PLACEHOLDER =
            Pattern.compile("\\$\\{([A-Za-z_]\\w*)(?::([^}]*))?}");

    private ConfigLoader() {}

    /**
     * Loads configuration and resolves placeholders from the process environment.
     *
     * @param path properties file to read
     * @return validated extension configuration
     * @throws IOException when the file cannot be read
     * @throws IllegalArgumentException when a property or environment value is missing or invalid
     */
    public static ExtensionConfig load(final Path path) throws IOException {
        return load(path, System::getenv);
    }

    /**
     * Loads configuration using the supplied environment lookup function.
     *
     * <p>This overload makes configuration resolution deterministic for callers that supply values
     * from a controlled environment. Placeholders use {@code ${NAME}} for required values and
     * {@code ${NAME:default}} for defaults.
     *
     * @param path properties file to read
     * @param environment lookup that returns a value or {@code null} for an unset variable
     * @return validated extension configuration
     * @throws IOException when the file cannot be read
     * @throws IllegalArgumentException when a property or environment value is missing or invalid
     */
    public static ExtensionConfig load(final Path path, final UnaryOperator<String> environment)
            throws IOException {
        Objects.requireNonNull(path, "path");
        Objects.requireNonNull(environment, "environment");

        final Properties source = new Properties();
        try (Reader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            source.load(reader);
        }

        final Properties properties = new Properties();
        for (String key : source.stringPropertyNames()) {
            properties.setProperty(key, resolve(source.getProperty(key), environment));
        }
        return toConfig(properties);
    }

    static String resolve(final String value, final UnaryOperator<String> environment) {
        final Matcher matcher = ENVIRONMENT_PLACEHOLDER.matcher(value);
        final StringBuilder resolved = new StringBuilder();
        while (matcher.find()) {
            final String variableName = matcher.group(1);
            final String environmentValue = environment.apply(variableName);
            final String replacement;
            if (environmentValue != null) {
                replacement = environmentValue;
            } else if (matcher.group(2) != null) {
                replacement = matcher.group(2);
            } else {
                throw new IllegalArgumentException(
                        "Required environment variable is not set: " + variableName);
            }
            matcher.appendReplacement(resolved, Matcher.quoteReplacement(replacement));
        }
        matcher.appendTail(resolved);
        return resolved.toString();
    }

    private static ExtensionConfig toConfig(final Properties properties) {
        final ExtensionConfig.Database database = new ExtensionConfig.Database(
                required(properties, "db.url"),
                required(properties, "db.username"),
                required(properties, "db.password"),
                integer(properties, "db.pool.maximum-size"),
                integer(properties, "db.pool.minimum-idle"),
                milliseconds(properties, "db.connection-timeout-ms"),
                milliseconds(properties, "db.validation-timeout-ms"),
                milliseconds(properties, "db.idle-timeout-ms"),
                milliseconds(properties, "db.max-lifetime-ms"),
                integer(properties, "db.query-timeout-seconds"));

        final ExtensionConfig.Queries queries = new ExtensionConfig.Queries(
                required(properties, "query.password"),
                required(properties, "query.superuser"),
                required(properties, "query.acl"),
                required(properties, "query.publish-action"),
                required(properties, "query.subscribe-action"));

        final ExtensionConfig.Cache cache = new ExtensionConfig.Cache(
                bool(properties, "cache.enabled"),
                seconds(properties, "cache.authentication-ttl-seconds"),
                seconds(properties, "cache.authorization-ttl-seconds"),
                seconds(properties, "cache.authentication-jitter-seconds"),
                seconds(properties, "cache.authorization-jitter-seconds"),
                longValue(properties, "cache.maximum-entries"));

        final ExtensionConfig.LocalSuperuser localSuperuser = new ExtensionConfig.LocalSuperuser(
                bool(properties, "local-superuser.enabled"),
                required(properties, "local-superuser.username"),
                required(properties, "local-superuser.password"));

        return new ExtensionConfig(
                database,
                queries,
                cache,
                localSuperuser,
                milliseconds(properties, "callback.timeout-ms"),
                integer(properties, "security.maximum-username-bytes"),
                integer(properties, "security.maximum-password-bytes"));
    }

    private static String required(final Properties properties, final String key) {
        final String value = properties.getProperty(key);
        if (value == null) {
            throw new IllegalArgumentException("Missing required configuration property: " + key);
        }
        return value;
    }

    private static int integer(final Properties properties, final String key) {
        try {
            return Integer.parseInt(required(properties, key).trim());
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException(key + " must be a valid integer", exception);
        }
    }

    private static long longValue(final Properties properties, final String key) {
        try {
            return Long.parseLong(required(properties, key).trim());
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException(key + " must be a valid long", exception);
        }
    }

    private static boolean bool(final Properties properties, final String key) {
        final String value = required(properties, key).trim();
        if ("true".equalsIgnoreCase(value)) {
            return true;
        }
        if ("false".equalsIgnoreCase(value)) {
            return false;
        }
        throw new IllegalArgumentException(key + " must be either true or false");
    }

    private static Duration milliseconds(final Properties properties, final String key) {
        return Duration.ofMillis(longValue(properties, key));
    }

    private static Duration seconds(final Properties properties, final String key) {
        return Duration.ofSeconds(longValue(properties, key));
    }
}
