package at.flexidata.eddie.mqtt.auth.hivemq;

import at.flexidata.eddie.mqtt.auth.security.AuthService;
import at.flexidata.eddie.mqtt.auth.security.AuthenticatedPrincipal;
import at.flexidata.eddie.mqtt.auth.security.MqttActivity;
import com.hivemq.extension.sdk.api.annotations.NotNull;
import com.hivemq.extension.sdk.api.async.Async;
import com.hivemq.extension.sdk.api.async.TimeoutFallback;
import com.hivemq.extension.sdk.api.auth.PublishAuthorizer;
import com.hivemq.extension.sdk.api.auth.SubscriptionAuthorizer;
import com.hivemq.extension.sdk.api.auth.parameter.PublishAuthorizerInput;
import com.hivemq.extension.sdk.api.auth.parameter.PublishAuthorizerOutput;
import com.hivemq.extension.sdk.api.auth.parameter.SubscriptionAuthorizerInput;
import com.hivemq.extension.sdk.api.auth.parameter.SubscriptionAuthorizerOutput;
import com.hivemq.extension.sdk.api.client.parameter.ConnectionAttributeStore;
import com.hivemq.extension.sdk.api.services.ManagedExtensionExecutorService;
import java.time.Duration;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * HiveMQ publish and subscription authorizer.
 *
 * <p>Cached decisions complete on the callback thread. Cache misses use the managed extension
 * executor so PostgreSQL access never blocks a HiveMQ event-loop thread.
 */
public final class DatabaseAuthorizer implements PublishAuthorizer, SubscriptionAuthorizer {

    private static final Logger LOGGER = LoggerFactory.getLogger(DatabaseAuthorizer.class);

    private final AuthService authService;
    private final ManagedExtensionExecutorService executorService;
    private final Duration timeout;

    /**
     * Creates a fail-closed authorizer.
     *
     * @param authService authorization service
     * @param executorService HiveMQ-managed executor used for blocking work
     * @param timeout asynchronous callback timeout
     */
    public DatabaseAuthorizer(
            final AuthService authService,
            final ManagedExtensionExecutorService executorService,
            final Duration timeout) {
        this.authService = authService;
        this.executorService = executorService;
        this.timeout = timeout;
    }

    /** {@inheritDoc} */
    @Override
    public void authorizePublish(
            final @NotNull PublishAuthorizerInput input,
            final @NotNull PublishAuthorizerOutput output) {
        final Optional<AuthenticatedPrincipal> principal = principal(input.getConnectionInformation()
                .getConnectionAttributeStore());
        if (principal.isEmpty()) {
            output.failAuthorization();
            return;
        }

        final AuthenticatedPrincipal authenticatedPrincipal = principal.orElseThrow();
        final String topic = input.getPublishPacket().getTopic();
        final Optional<Boolean> cachedDecision =
                authService.authorizeFromCache(authenticatedPrincipal, MqttActivity.PUBLISH, topic);
        if (cachedDecision.isPresent()) {
            if (cachedDecision.orElseThrow()) {
                output.authorizeSuccessfully();
            } else {
                output.failAuthorization();
            }
            return;
        }

        final Async<PublishAuthorizerOutput> async = output.async(timeout, TimeoutFallback.FAILURE);
        final String clientId = input.getClientInformation().getClientId();
        AsyncAuthorization.submit(
                executorService,
                () -> authService.authorize(authenticatedPrincipal, MqttActivity.PUBLISH, topic),
                output::authorizeSuccessfully,
                output::failAuthorization,
                async,
                exception -> LOGGER.warn("Publish authorization failed for client {}", clientId, exception));
    }

    /** {@inheritDoc} */
    @Override
    public void authorizeSubscribe(
            final @NotNull SubscriptionAuthorizerInput input,
            final @NotNull SubscriptionAuthorizerOutput output) {
        final Optional<AuthenticatedPrincipal> principal = principal(input.getConnectionInformation()
                .getConnectionAttributeStore());
        if (principal.isEmpty()) {
            output.failAuthorization();
            return;
        }

        final AuthenticatedPrincipal authenticatedPrincipal = principal.orElseThrow();
        final String topicFilter = input.getSubscription().getTopicFilter();
        final Optional<Boolean> cachedDecision =
                authService.authorizeFromCache(authenticatedPrincipal, MqttActivity.SUBSCRIBE, topicFilter);
        if (cachedDecision.isPresent()) {
            if (cachedDecision.orElseThrow()) {
                output.authorizeSuccessfully();
            } else {
                output.failAuthorization();
            }
            return;
        }

        final Async<SubscriptionAuthorizerOutput> async = output.async(timeout, TimeoutFallback.FAILURE);
        final String clientId = input.getClientInformation().getClientId();
        AsyncAuthorization.submit(
                executorService,
                () -> authService.authorize(authenticatedPrincipal, MqttActivity.SUBSCRIBE, topicFilter),
                output::authorizeSuccessfully,
                output::failAuthorization,
                async,
                exception -> LOGGER.warn("Subscription authorization failed for client {}", clientId, exception));
    }

    private static Optional<AuthenticatedPrincipal> principal(final ConnectionAttributeStore attributes) {
        return PrincipalAttributes.get(attributes);
    }
}
