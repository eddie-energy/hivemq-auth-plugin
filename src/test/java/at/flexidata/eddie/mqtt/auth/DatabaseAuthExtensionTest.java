package at.flexidata.eddie.mqtt.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import at.flexidata.eddie.mqtt.auth.repository.PostgresAuthRepository;
import at.flexidata.eddie.mqtt.auth.security.AuthService;
import com.hivemq.extension.sdk.api.parameter.ExtensionInformation;
import com.hivemq.extension.sdk.api.parameter.ExtensionStartInput;
import com.hivemq.extension.sdk.api.parameter.ExtensionStartOutput;
import com.hivemq.extension.sdk.api.parameter.ExtensionStopInput;
import com.hivemq.extension.sdk.api.parameter.ExtensionStopOutput;
import com.hivemq.extension.sdk.api.services.ManagedExtensionExecutorService;
import com.hivemq.extension.sdk.api.services.Services;
import com.hivemq.extension.sdk.api.services.auth.SecurityRegistry;
import com.hivemq.extension.sdk.api.services.intializer.InitializerRegistry;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;

class DatabaseAuthExtensionTest {

    @TempDir
    Path extensionHome;

    @Test
    void resolvesConfiguredOrExtensionHomeConfigurationPath() {
        final ExtensionInformation information = mock(ExtensionInformation.class);
        when(information.getExtensionHomeFolder()).thenReturn(extensionHome.toFile());
        final Path customPath = extensionHome.resolve("custom.properties");

        assertEquals(
                customPath,
                DatabaseAuthExtension.configPath(
                        information,
                        variable -> "HIVEMQ_AUTH_CONFIG".equals(variable) ? customPath.toString() : null));
        assertEquals(
                extensionHome.resolve("extension.properties"),
                DatabaseAuthExtension.configPath(information, ignored -> "  "));
    }

    @Test
    void registersSecurityComponentsAndClosesOwnedService() throws IOException {
        writeValidConfiguration();
        final ExtensionInformation information = extensionInformation();
        final ExtensionStartInput startInput = mock(ExtensionStartInput.class);
        final ExtensionStartOutput startOutput = mock(ExtensionStartOutput.class);
        final ExtensionStopInput stopInput = mock(ExtensionStopInput.class);
        final ExtensionStopOutput stopOutput = mock(ExtensionStopOutput.class);
        final ManagedExtensionExecutorService executor = mock(ManagedExtensionExecutorService.class);
        final SecurityRegistry securityRegistry = mock(SecurityRegistry.class);
        final InitializerRegistry initializerRegistry = mock(InitializerRegistry.class);
        when(startInput.getExtensionInformation()).thenReturn(information);
        when(stopInput.getExtensionInformation()).thenReturn(information);

        try (MockedStatic<Services> hiveMqServices = mockStatic(Services.class);
                MockedConstruction<PostgresAuthRepository> repositories =
                        mockConstruction(PostgresAuthRepository.class);
                MockedConstruction<AuthService> authServices = mockConstruction(AuthService.class)) {
            hiveMqServices.when(Services::extensionExecutorService).thenReturn(executor);
            hiveMqServices.when(Services::securityRegistry).thenReturn(securityRegistry);
            hiveMqServices.when(Services::initializerRegistry).thenReturn(initializerRegistry);
            final DatabaseAuthExtension extension = new DatabaseAuthExtension();

            extension.extensionStart(startInput, startOutput);

            assertEquals(1, repositories.constructed().size());
            assertEquals(1, authServices.constructed().size());
            verify(securityRegistry).setAuthenticatorProvider(any());
            verify(securityRegistry).setAuthorizerProvider(any());
            verify(initializerRegistry).setClientInitializer(any());
            verify(startOutput, never()).preventExtensionStartup(any());

            extension.extensionStop(stopInput, stopOutput);
            extension.extensionStop(stopInput, stopOutput);
            verify(authServices.constructed().getFirst(), times(1)).close();
        }
    }

    @Test
    void preventsStartupForInvalidConfiguration() throws IOException {
        Files.writeString(extensionHome.resolve("extension.properties"), "db.url=not-postgresql\n");
        final ExtensionStartInput input = mock(ExtensionStartInput.class);
        final ExtensionStartOutput output = mock(ExtensionStartOutput.class);
        final ExtensionInformation information = extensionInformation();
        when(input.getExtensionInformation()).thenReturn(information);

        new DatabaseAuthExtension().extensionStart(input, output);

        verify(output).preventExtensionStartup(any());
    }

    @Test
    void closesServiceWhenHiveMqRegistrationFails() throws IOException {
        writeValidConfiguration();
        final ExtensionStartInput input = mock(ExtensionStartInput.class);
        final ExtensionStartOutput output = mock(ExtensionStartOutput.class);
        final ExtensionInformation information = extensionInformation();
        when(input.getExtensionInformation()).thenReturn(information);

        try (MockedStatic<Services> hiveMqServices = mockStatic(Services.class);
                MockedConstruction<PostgresAuthRepository> repositories =
                        mockConstruction(PostgresAuthRepository.class);
                MockedConstruction<AuthService> authServices = mockConstruction(AuthService.class)) {
            hiveMqServices
                    .when(Services::extensionExecutorService)
                    .thenThrow(new IllegalStateException("HiveMQ is stopping"));

            new DatabaseAuthExtension().extensionStart(input, output);

            assertEquals(1, repositories.constructed().size());
            verify(authServices.constructed().getFirst()).close();
            verify(output).preventExtensionStartup(any());
        }
    }

    private ExtensionInformation extensionInformation() {
        final ExtensionInformation information = mock(ExtensionInformation.class);
        when(information.getExtensionHomeFolder()).thenReturn(extensionHome.toFile());
        when(information.getName()).thenReturn("EDDIE PostgreSQL Authentication");
        when(information.getVersion()).thenReturn("test");
        return information;
    }

    private void writeValidConfiguration() throws IOException {
        Files.writeString(
                extensionHome.resolve("extension.properties"),
                """
                db.url=jdbc:postgresql://localhost:5432/eddie
                db.username=emqx
                db.password=test-password
                db.pool.maximum-size=2
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
                cache.enabled=true
                cache.authentication-ttl-seconds=300
                cache.authorization-ttl-seconds=300
                cache.authentication-jitter-seconds=0
                cache.authorization-jitter-seconds=0
                cache.maximum-entries=100
                local-superuser.enabled=false
                local-superuser.username=eddie
                local-superuser.password=
                callback.timeout-ms=5000
                security.maximum-username-bytes=1024
                security.maximum-password-bytes=4096
                """);
    }
}
