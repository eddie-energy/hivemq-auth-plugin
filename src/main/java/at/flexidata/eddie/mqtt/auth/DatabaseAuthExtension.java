package at.flexidata.eddie.mqtt.auth;

import at.flexidata.eddie.mqtt.auth.config.ConfigLoader;
import at.flexidata.eddie.mqtt.auth.config.ExtensionConfig;
import at.flexidata.eddie.mqtt.auth.hivemq.DatabaseAuthenticator;
import at.flexidata.eddie.mqtt.auth.hivemq.DatabaseAuthorizer;
import at.flexidata.eddie.mqtt.auth.hivemq.OutboundReadAuthorizer;
import at.flexidata.eddie.mqtt.auth.repository.PostgresAuthRepository;
import at.flexidata.eddie.mqtt.auth.security.AuthService;
import at.flexidata.eddie.mqtt.auth.security.BcryptPasswordVerifier;
import com.hivemq.extension.sdk.api.ExtensionMain;
import com.hivemq.extension.sdk.api.annotations.NotNull;
import com.hivemq.extension.sdk.api.parameter.ExtensionInformation;
import com.hivemq.extension.sdk.api.parameter.ExtensionStartInput;
import com.hivemq.extension.sdk.api.parameter.ExtensionStartOutput;
import com.hivemq.extension.sdk.api.parameter.ExtensionStopInput;
import com.hivemq.extension.sdk.api.parameter.ExtensionStopOutput;
import com.hivemq.extension.sdk.api.services.ManagedExtensionExecutorService;
import com.hivemq.extension.sdk.api.services.Services;
import com.hivemq.extension.sdk.api.services.auth.SecurityRegistry;
import java.nio.file.Path;
import java.util.function.UnaryOperator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * HiveMQ extension entry point that wires PostgreSQL-backed authentication and authorization into
 * the broker lifecycle.
 *
 * <p>Startup is fail-closed: invalid configuration or a component-initialization failure prevents
 * the extension from starting. The owned {@link AuthService} and its database pool are closed when
 * HiveMQ stops the extension.
 */
public final class DatabaseAuthExtension implements ExtensionMain {

    private static final Logger LOGGER = LoggerFactory.getLogger(DatabaseAuthExtension.class);
    private static final String CONFIG_PATH_ENVIRONMENT_VARIABLE = "HIVEMQ_AUTH_CONFIG";
    private static final String DEFAULT_CONFIG_FILE = "extension.properties";

    private AuthService authService;

    /** Creates an extension entry point for HiveMQ's service loader. */
    public DatabaseAuthExtension() {
        // HiveMQ's service loader requires a public no-argument constructor.
    }

    /** {@inheritDoc} */
    @Override
    @SuppressWarnings("java:S2095") // AuthService owns the repository after successful construction.
    public void extensionStart(
            final @NotNull ExtensionStartInput input, final @NotNull ExtensionStartOutput output) {
        AuthService service = null;
        PostgresAuthRepository repository = null;
        try {
            final Path configPath = configPath(input.getExtensionInformation());
            final ExtensionConfig config = ConfigLoader.load(configPath);
            repository = new PostgresAuthRepository(config.database(), config.queries());
            service = new AuthService(repository, new BcryptPasswordVerifier(), config);

            final ManagedExtensionExecutorService executor = Services.extensionExecutorService();
            final SecurityRegistry securityRegistry = Services.securityRegistry();
            final DatabaseAuthenticator authenticator =
                    new DatabaseAuthenticator(service, executor, config.callbackTimeout());
            final DatabaseAuthorizer authorizer =
                    new DatabaseAuthorizer(service, executor, config.callbackTimeout());
            final OutboundReadAuthorizer outboundReadAuthorizer =
                    new OutboundReadAuthorizer(service, executor, config.callbackTimeout());
            securityRegistry.setAuthenticatorProvider(ignored -> authenticator);
            securityRegistry.setAuthorizerProvider(ignored -> authorizer);
            Services.initializerRegistry().setClientInitializer(
                    (ignored, clientContext) ->
                            clientContext.addPublishOutboundInterceptor(outboundReadAuthorizer));

            authService = service;
            LOGGER.info(
                    "Started {} version {} with PostgreSQL authentication and authorization",
                    input.getExtensionInformation().getName(),
                    input.getExtensionInformation().getVersion());
        } catch (Exception exception) {
            if (service != null) {
                service.close();
            } else if (repository != null) {
                repository.close();
            }
            LOGGER.error("Unable to start the EDDIE PostgreSQL authentication extension", exception);
            output.preventExtensionStartup("Invalid extension configuration or initialization failure; see HiveMQ logs");
        }
    }

    /** {@inheritDoc} */
    @Override
    public void extensionStop(
            final @NotNull ExtensionStopInput input, final @NotNull ExtensionStopOutput output) {
        if (authService != null) {
            authService.close();
            authService = null;
        }
        LOGGER.info(
                "Stopped {} version {}",
                input.getExtensionInformation().getName(),
                input.getExtensionInformation().getVersion());
    }

    static Path configPath(final ExtensionInformation information) {
        return configPath(information, System::getenv);
    }

    static Path configPath(
            final ExtensionInformation information, final UnaryOperator<String> environment) {
        final String configuredPath = environment.apply(CONFIG_PATH_ENVIRONMENT_VARIABLE);
        if (configuredPath != null && !configuredPath.isBlank()) {
            return Path.of(configuredPath);
        }
        return information.getExtensionHomeFolder().toPath().resolve(DEFAULT_CONFIG_FILE);
    }
}
