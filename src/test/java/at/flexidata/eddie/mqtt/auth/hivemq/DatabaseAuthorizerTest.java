package at.flexidata.eddie.mqtt.auth.hivemq;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import at.flexidata.eddie.mqtt.auth.security.AuthService;
import at.flexidata.eddie.mqtt.auth.security.AuthenticatedPrincipal;
import at.flexidata.eddie.mqtt.auth.security.MqttActivity;
import com.hivemq.extension.sdk.api.async.Async;
import com.hivemq.extension.sdk.api.auth.parameter.PublishAuthorizerInput;
import com.hivemq.extension.sdk.api.auth.parameter.PublishAuthorizerOutput;
import com.hivemq.extension.sdk.api.auth.parameter.SubscriptionAuthorizerInput;
import com.hivemq.extension.sdk.api.auth.parameter.SubscriptionAuthorizerOutput;
import com.hivemq.extension.sdk.api.client.parameter.ClientInformation;
import com.hivemq.extension.sdk.api.client.parameter.ConnectionAttributeStore;
import com.hivemq.extension.sdk.api.client.parameter.ConnectionInformation;
import com.hivemq.extension.sdk.api.packets.publish.PublishPacket;
import com.hivemq.extension.sdk.api.packets.subscribe.Subscription;
import com.hivemq.extension.sdk.api.services.ManagedExtensionExecutorService;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.RejectedExecutionException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class DatabaseAuthorizerTest {

    private AuthService authService;
    private ManagedExtensionExecutorService executorService;
    private ConnectionAttributeStore attributes;
    private DatabaseAuthorizer authorizer;

    @BeforeEach
    void setUp() {
        authService = mock(AuthService.class);
        executorService = mock(ManagedExtensionExecutorService.class);
        attributes = mock(ConnectionAttributeStore.class);
        doAnswer(invocation -> {
                    invocation.<Runnable>getArgument(0).run();
                    return CompletableFuture.completedFuture(null);
                })
                .when(executorService)
                .submit(any(Runnable.class));
        authorizer = new DatabaseAuthorizer(authService, executorService, Duration.ofSeconds(2));
    }

    @Test
    void authorizesAllowedPublishAndFailsDeniedPublish() {
        final PublishFixture allowed = publishFixture("sensors/kitchen");
        principal();
        when(authService.authorize(
                        new AuthenticatedPrincipal("alice", false), MqttActivity.PUBLISH, "sensors/kitchen"))
                .thenReturn(true);
        authorizer.authorizePublish(allowed.input(), allowed.output());
        verify(allowed.output()).authorizeSuccessfully();
        verify(allowed.async()).resume();

        final PublishFixture denied = publishFixture("private/data");
        authorizer.authorizePublish(denied.input(), denied.output());
        verify(denied.output()).failAuthorization();
        verify(denied.async()).resume();
    }

    @Test
    void authorizesSubscriptionUsingAuthenticatedConnectionPrincipal() {
        final SubscriptionFixture fixture = subscriptionFixture("events/+/status");
        principal();
        when(authService.authorize(
                        new AuthenticatedPrincipal("alice", false),
                        MqttActivity.SUBSCRIBE,
                        "events/+/status"))
                .thenReturn(true);

        authorizer.authorizeSubscribe(fixture.input(), fixture.output());

        verify(fixture.output()).authorizeSuccessfully();
        verify(fixture.async()).resume();
    }

    @Test
    void completesCachedPublishDecisionsWithoutUsingTheManagedExecutor() {
        principal();
        final AuthenticatedPrincipal alice = new AuthenticatedPrincipal("alice", false);
        final PublishFixture allowed = publishFixture("sensors/allowed");
        final PublishFixture denied = publishFixture("sensors/denied");
        when(authService.authorizeFromCache(alice, MqttActivity.PUBLISH, "sensors/allowed"))
                .thenReturn(Optional.of(true));
        when(authService.authorizeFromCache(alice, MqttActivity.PUBLISH, "sensors/denied"))
                .thenReturn(Optional.of(false));

        authorizer.authorizePublish(allowed.input(), allowed.output());
        authorizer.authorizePublish(denied.input(), denied.output());

        verify(allowed.output()).authorizeSuccessfully();
        verify(allowed.output(), never()).async(any(), any());
        verify(denied.output()).failAuthorization();
        verify(denied.output(), never()).async(any(), any());
        verify(executorService, never()).submit(any(Runnable.class));
        verify(authService, never()).authorize(any(), any(), any());
    }

    @Test
    void completesCachedSubscriptionDecisionsWithoutUsingTheManagedExecutor() {
        principal();
        final AuthenticatedPrincipal alice = new AuthenticatedPrincipal("alice", false);
        final SubscriptionFixture allowed = subscriptionFixture("events/allowed");
        final SubscriptionFixture denied = subscriptionFixture("events/denied");
        when(authService.authorizeFromCache(alice, MqttActivity.SUBSCRIBE, "events/allowed"))
                .thenReturn(Optional.of(true));
        when(authService.authorizeFromCache(alice, MqttActivity.SUBSCRIBE, "events/denied"))
                .thenReturn(Optional.of(false));

        authorizer.authorizeSubscribe(allowed.input(), allowed.output());
        authorizer.authorizeSubscribe(denied.input(), denied.output());

        verify(allowed.output()).authorizeSuccessfully();
        verify(allowed.output(), never()).async(any(), any());
        verify(denied.output()).failAuthorization();
        verify(denied.output(), never()).async(any(), any());
        verify(executorService, never()).submit(any(Runnable.class));
        verify(authService, never()).authorize(any(), any(), any());
    }

    @Test
    void failsImmediatelyWhenConnectionHasNoPrincipal() {
        final PublishFixture fixture = publishFixture("topic");
        when(attributes.getAsString("eddie.mqtt.auth.username")).thenReturn(Optional.empty());

        authorizer.authorizePublish(fixture.input(), fixture.output());

        verify(fixture.output()).failAuthorization();
        verify(fixture.output(), never()).async(any(), any());
        verify(authService, never()).authorize(any(), any(), any());
    }

    @Test
    void failsClosedOnBackendErrorAndExecutorRejection() {
        final PublishFixture backendFailure = publishFixture("topic");
        principal();
        when(authService.authorize(any(), eq(MqttActivity.PUBLISH), eq("topic")))
                .thenThrow(new IllegalStateException("database unavailable"));
        authorizer.authorizePublish(backendFailure.input(), backendFailure.output());
        verify(backendFailure.output()).failAuthorization();
        verify(backendFailure.async()).resume();

        final PublishFixture rejected = publishFixture("other");
        doThrow(new RejectedExecutionException("stopping"))
                .when(executorService)
                .submit(any(Runnable.class));
        authorizer.authorizePublish(rejected.input(), rejected.output());
        verify(rejected.output()).failAuthorization();
        verify(rejected.async()).resume();
    }

    private void principal() {
        when(attributes.getAsString("eddie.mqtt.auth.username")).thenReturn(Optional.of("alice"));
        when(attributes.getAsString("eddie.mqtt.auth.local-superuser"))
                .thenReturn(Optional.of(Boolean.FALSE.toString()));
    }

    @SuppressWarnings("unchecked")
    private PublishFixture publishFixture(final String topic) {
        final PublishAuthorizerInput input = mock(PublishAuthorizerInput.class);
        final PublishAuthorizerOutput output = mock(PublishAuthorizerOutput.class);
        final PublishPacket packet = mock(PublishPacket.class);
        final Async<PublishAuthorizerOutput> async = (Async<PublishAuthorizerOutput>) mock(Async.class);
        commonInput(input);
        when(input.getPublishPacket()).thenReturn(packet);
        when(packet.getTopic()).thenReturn(topic);
        when(output.async(any(), any())).thenReturn(async);
        return new PublishFixture(input, output, async);
    }

    @SuppressWarnings("unchecked")
    private SubscriptionFixture subscriptionFixture(final String topicFilter) {
        final SubscriptionAuthorizerInput input = mock(SubscriptionAuthorizerInput.class);
        final SubscriptionAuthorizerOutput output = mock(SubscriptionAuthorizerOutput.class);
        final Subscription subscription = mock(Subscription.class);
        final Async<SubscriptionAuthorizerOutput> async =
                (Async<SubscriptionAuthorizerOutput>) mock(Async.class);
        commonInput(input);
        when(input.getSubscription()).thenReturn(subscription);
        when(subscription.getTopicFilter()).thenReturn(topicFilter);
        when(output.async(any(), any())).thenReturn(async);
        return new SubscriptionFixture(input, output, async);
    }

    private void commonInput(final com.hivemq.extension.sdk.api.parameter.ClientBasedInput input) {
        final ConnectionInformation connectionInformation = mock(ConnectionInformation.class);
        final ClientInformation clientInformation = mock(ClientInformation.class);
        when(input.getConnectionInformation()).thenReturn(connectionInformation);
        when(connectionInformation.getConnectionAttributeStore()).thenReturn(attributes);
        when(input.getClientInformation()).thenReturn(clientInformation);
        when(clientInformation.getClientId()).thenReturn("client-1");
    }

    private record PublishFixture(
            PublishAuthorizerInput input,
            PublishAuthorizerOutput output,
            Async<PublishAuthorizerOutput> async) {}

    private record SubscriptionFixture(
            SubscriptionAuthorizerInput input,
            SubscriptionAuthorizerOutput output,
            Async<SubscriptionAuthorizerOutput> async) {}
}
