package at.flexidata.eddie.mqtt.auth.hivemq;

import at.flexidata.eddie.mqtt.auth.security.AuthService;
import at.flexidata.eddie.mqtt.auth.security.AuthenticatedPrincipal;
import at.flexidata.eddie.mqtt.auth.security.MqttActivity;
import com.hivemq.extension.sdk.api.annotations.NotNull;
import com.hivemq.extension.sdk.api.async.Async;
import com.hivemq.extension.sdk.api.async.TimeoutFallback;
import com.hivemq.extension.sdk.api.client.parameter.ConnectionAttributeStore;
import com.hivemq.extension.sdk.api.interceptor.publish.PublishOutboundInterceptor;
import com.hivemq.extension.sdk.api.interceptor.publish.parameter.PublishOutboundInput;
import com.hivemq.extension.sdk.api.interceptor.publish.parameter.PublishOutboundOutput;
import com.hivemq.extension.sdk.api.services.ManagedExtensionExecutorService;
import java.time.Duration;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Re-authorizes outbound publishes against subscribe ACLs before delivery.
 *
 * <p>This check makes ACL expiry effective for subscriptions that remain active after their rules
 * change. Missing principals, denials, timeouts, and backend failures prevent delivery.
 */
public final class OutboundReadAuthorizer implements PublishOutboundInterceptor {

    private static final Logger LOGGER = LoggerFactory.getLogger(OutboundReadAuthorizer.class);

    private final AuthService authService;
    private final ManagedExtensionExecutorService executorService;
    private final Duration timeout;

    /**
     * Creates a fail-closed outbound delivery authorizer.
     *
     * @param authService authorization service
     * @param executorService HiveMQ-managed executor used for blocking work
     * @param timeout asynchronous callback timeout
     */
    public OutboundReadAuthorizer(
            final AuthService authService,
            final ManagedExtensionExecutorService executorService,
            final Duration timeout) {
        this.authService = authService;
        this.executorService = executorService;
        this.timeout = timeout;
    }

    /** {@inheritDoc} */
    @Override
    public void onOutboundPublish(
            final @NotNull PublishOutboundInput input, final @NotNull PublishOutboundOutput output) {
        final ConnectionAttributeStore attributes =
                input.getConnectionInformation().getConnectionAttributeStore();
        final Optional<AuthenticatedPrincipal> principal = PrincipalAttributes.get(attributes);
        if (principal.isEmpty()) {
            output.preventPublishDelivery();
            return;
        }

        final AuthenticatedPrincipal authenticatedPrincipal = principal.orElseThrow();
        final String topic = input.getPublishPacket().getTopic();
        final Optional<Boolean> cachedDecision =
                authService.authorizeFromCache(authenticatedPrincipal, MqttActivity.SUBSCRIBE, topic);
        if (cachedDecision.isPresent()) {
            if (!cachedDecision.orElseThrow()) {
                output.preventPublishDelivery();
            }
            return;
        }

        final String clientId = input.getClientInformation().getClientId();
        final Async<PublishOutboundOutput> async = output.async(timeout, TimeoutFallback.FAILURE);
        AsyncAuthorization.submit(
                executorService,
                () -> authService.authorize(authenticatedPrincipal, MqttActivity.SUBSCRIBE, topic),
                () -> {
                    // An allowed outbound publish needs no output mutation.
                },
                output::preventPublishDelivery,
                async,
                exception -> LOGGER.warn("Outbound read authorization failed for client {}", clientId, exception));
    }
}
