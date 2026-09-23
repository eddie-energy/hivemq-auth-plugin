package at.flexidata.eddie.mqtt.auth.hivemq;

import at.flexidata.eddie.mqtt.auth.security.AuthService;
import at.flexidata.eddie.mqtt.auth.security.AuthenticatedPrincipal;
import com.hivemq.extension.sdk.api.annotations.NotNull;
import com.hivemq.extension.sdk.api.async.Async;
import com.hivemq.extension.sdk.api.async.TimeoutFallback;
import com.hivemq.extension.sdk.api.auth.SimpleAuthenticator;
import com.hivemq.extension.sdk.api.auth.parameter.SimpleAuthInput;
import com.hivemq.extension.sdk.api.auth.parameter.SimpleAuthOutput;
import com.hivemq.extension.sdk.api.packets.connect.ConnectPacket;
import com.hivemq.extension.sdk.api.services.ManagedExtensionExecutorService;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.Arrays;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * HiveMQ CONNECT authenticator that runs credential checks on the managed extension executor.
 *
 * <p>Missing, oversized, invalid, timed-out, or backend-failing credentials are denied.
 */
public final class DatabaseAuthenticator implements SimpleAuthenticator {

    private static final Logger LOGGER = LoggerFactory.getLogger(DatabaseAuthenticator.class);

    private final AuthService authService;
    private final ManagedExtensionExecutorService executorService;
    private final Duration timeout;

    /**
     * Creates a fail-closed authenticator.
     *
     * @param authService authentication service
     * @param executorService HiveMQ-managed executor used for blocking work
     * @param timeout asynchronous callback timeout
     */
    public DatabaseAuthenticator(
            final AuthService authService,
            final ManagedExtensionExecutorService executorService,
            final Duration timeout) {
        this.authService = authService;
        this.executorService = executorService;
        this.timeout = timeout;
    }

    /** {@inheritDoc} */
    @Override
    public void onConnect(
            final @NotNull SimpleAuthInput input, final @NotNull SimpleAuthOutput output) {
        final ConnectPacket connectPacket = input.getConnectPacket();
        final Optional<String> username = connectPacket.getUserName();
        final Optional<ByteBuffer> passwordBuffer = connectPacket.getPassword();
        if (username.isEmpty()
                || passwordBuffer.isEmpty()
                || !authService.credentialsWithinLimits(username.orElseThrow(), passwordBuffer.orElseThrow().remaining())) {
            output.failAuthentication();
            return;
        }

        final byte[] password = copy(passwordBuffer.orElseThrow());
        final Async<SimpleAuthOutput> async = output.async(timeout, TimeoutFallback.FAILURE);
        try {
            executorService.submit(() -> authenticate(input, output, async, username.orElseThrow(), password));
        } catch (RuntimeException exception) {
            Arrays.fill(password, (byte) 0);
            LOGGER.warn("Authentication task submission failed", exception);
            output.failAuthentication();
            async.resume();
        }
    }

    private void authenticate(
            final SimpleAuthInput input,
            final SimpleAuthOutput output,
            final Async<SimpleAuthOutput> async,
            final String username,
            final byte[] password) {
        try {
            final Optional<AuthenticatedPrincipal> principal = authService.authenticate(username, password);
            if (principal.isPresent()) {
                PrincipalAttributes.put(
                        input.getConnectionInformation().getConnectionAttributeStore(), principal.orElseThrow());
                output.authenticateSuccessfully(true);
            } else {
                output.failAuthentication();
            }
        } catch (RuntimeException exception) {
            LOGGER.warn(
                    "Authentication backend failed for client {}",
                    input.getClientInformation().getClientId(),
                    exception);
            output.failAuthentication();
        } finally {
            Arrays.fill(password, (byte) 0);
            async.resume();
        }
    }

    private static byte[] copy(final ByteBuffer source) {
        final ByteBuffer duplicate = source.asReadOnlyBuffer();
        final byte[] copy = new byte[duplicate.remaining()];
        duplicate.get(copy);
        return copy;
    }
}
