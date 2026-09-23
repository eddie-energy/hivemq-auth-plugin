package at.flexidata.eddie.mqtt.auth.hivemq;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import at.flexidata.eddie.mqtt.auth.security.AuthService;
import at.flexidata.eddie.mqtt.auth.security.AuthenticatedPrincipal;
import com.hivemq.extension.sdk.api.async.Async;
import com.hivemq.extension.sdk.api.auth.parameter.SimpleAuthInput;
import com.hivemq.extension.sdk.api.auth.parameter.SimpleAuthOutput;
import com.hivemq.extension.sdk.api.client.parameter.ClientInformation;
import com.hivemq.extension.sdk.api.client.parameter.ConnectionAttributeStore;
import com.hivemq.extension.sdk.api.client.parameter.ConnectionInformation;
import com.hivemq.extension.sdk.api.packets.connect.ConnectPacket;
import com.hivemq.extension.sdk.api.services.ManagedExtensionExecutorService;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.RejectedExecutionException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class DatabaseAuthenticatorTest {

    private AuthService authService;
    private ManagedExtensionExecutorService executorService;
    private SimpleAuthInput input;
    private SimpleAuthOutput output;
    private ConnectPacket connectPacket;
    private ConnectionAttributeStore attributes;
    private Async<SimpleAuthOutput> async;
    private DatabaseAuthenticator authenticator;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        authService = mock(AuthService.class);
        executorService = mock(ManagedExtensionExecutorService.class);
        input = mock(SimpleAuthInput.class);
        output = mock(SimpleAuthOutput.class);
        connectPacket = mock(ConnectPacket.class);
        attributes = mock(ConnectionAttributeStore.class);
        async = (Async<SimpleAuthOutput>) mock(Async.class);
        final ConnectionInformation connectionInformation = mock(ConnectionInformation.class);
        final ClientInformation clientInformation = mock(ClientInformation.class);

        when(input.getConnectPacket()).thenReturn(connectPacket);
        when(input.getConnectionInformation()).thenReturn(connectionInformation);
        when(connectionInformation.getConnectionAttributeStore()).thenReturn(attributes);
        when(input.getClientInformation()).thenReturn(clientInformation);
        when(clientInformation.getClientId()).thenReturn("client-1");
        when(output.async(any(), any())).thenReturn(async);
        doAnswer(invocation -> {
                    invocation.<Runnable>getArgument(0).run();
                    return CompletableFuture.completedFuture(null);
                })
                .when(executorService)
                .submit(any(Runnable.class));

        authenticator = new DatabaseAuthenticator(authService, executorService, Duration.ofSeconds(2));
    }

    @Test
    void authenticatesAndStoresPrincipalAsynchronously() {
        credentials();
        when(authService.credentialsWithinLimits("alice", 6)).thenReturn(true);
        when(authService.authenticate(eq("alice"), any(byte[].class)))
                .thenReturn(Optional.of(new AuthenticatedPrincipal("alice", false)));

        authenticator.onConnect(input, output);

        verify(output).authenticateSuccessfully(true);
        verify(attributes).putAsString("eddie.mqtt.auth.username", "alice");
        verify(async).resume();
        verify(output, never()).failAuthentication();
    }

    @Test
    void rejectsMissingOrOversizedCredentialsBeforeCreatingAsyncOutput() {
        when(connectPacket.getUserName()).thenReturn(Optional.empty());
        when(connectPacket.getPassword()).thenReturn(Optional.empty());
        authenticator.onConnect(input, output);
        verify(output).failAuthentication();
        verify(output, never()).async(any(), any());

        final SimpleAuthOutput oversizedOutput = mock(SimpleAuthOutput.class);
        credentials();
        when(authService.credentialsWithinLimits("alice", 6)).thenReturn(false);
        authenticator.onConnect(input, oversizedOutput);
        verify(oversizedOutput).failAuthentication();
        verify(oversizedOutput, never()).async(any(), any());
    }

    @Test
    void failsClosedWhenCredentialsDoNotMatchOrBackendFails() {
        credentials();
        when(authService.credentialsWithinLimits("alice", 6)).thenReturn(true);
        when(authService.authenticate(eq("alice"), any(byte[].class))).thenReturn(Optional.empty());
        authenticator.onConnect(input, output);
        verify(output).failAuthentication();
        verify(async).resume();

        final SimpleAuthOutput failingOutput = mock(SimpleAuthOutput.class);
        final Async<SimpleAuthOutput> failingAsync = asyncOutput(failingOutput);
        when(authService.authenticate(eq("alice"), any(byte[].class)))
                .thenThrow(new IllegalStateException("database unavailable"));
        authenticator.onConnect(input, failingOutput);
        verify(failingOutput).failAuthentication();
        verify(failingAsync).resume();
    }

    @Test
    void failsClosedWhenExecutorRejectsTask() {
        credentials();
        when(authService.credentialsWithinLimits("alice", 6)).thenReturn(true);
        doThrow(new RejectedExecutionException("stopping"))
                .when(executorService)
                .submit(any(Runnable.class));

        authenticator.onConnect(input, output);

        verify(output).failAuthentication();
        verify(async).resume();
        verify(authService, never()).authenticate(anyString(), any(byte[].class));
    }

    private void credentials() {
        when(connectPacket.getUserName()).thenReturn(Optional.of("alice"));
        when(connectPacket.getPassword())
                .thenReturn(Optional.of(ByteBuffer.wrap("secret".getBytes(StandardCharsets.UTF_8)).asReadOnlyBuffer()));
    }

    @SuppressWarnings("unchecked")
    private static Async<SimpleAuthOutput> asyncOutput(final SimpleAuthOutput authOutput) {
        final Async<SimpleAuthOutput> result = (Async<SimpleAuthOutput>) mock(Async.class);
        when(authOutput.async(any(), any())).thenReturn(result);
        return result;
    }
}
