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
import com.hivemq.extension.sdk.api.client.parameter.ClientInformation;
import com.hivemq.extension.sdk.api.client.parameter.ConnectionAttributeStore;
import com.hivemq.extension.sdk.api.client.parameter.ConnectionInformation;
import com.hivemq.extension.sdk.api.interceptor.publish.parameter.PublishOutboundInput;
import com.hivemq.extension.sdk.api.interceptor.publish.parameter.PublishOutboundOutput;
import com.hivemq.extension.sdk.api.packets.publish.PublishPacket;
import com.hivemq.extension.sdk.api.services.ManagedExtensionExecutorService;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.RejectedExecutionException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class OutboundReadAuthorizerTest {

    private AuthService authService;
    private ManagedExtensionExecutorService executorService;
    private PublishOutboundInput input;
    private PublishOutboundOutput output;
    private ConnectionAttributeStore attributes;
    private Async<PublishOutboundOutput> async;
    private OutboundReadAuthorizer authorizer;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        authService = mock(AuthService.class);
        executorService = mock(ManagedExtensionExecutorService.class);
        input = mock(PublishOutboundInput.class);
        output = mock(PublishOutboundOutput.class);
        attributes = mock(ConnectionAttributeStore.class);
        async = (Async<PublishOutboundOutput>) mock(Async.class);
        final ConnectionInformation connectionInformation = mock(ConnectionInformation.class);
        final ClientInformation clientInformation = mock(ClientInformation.class);
        final PublishPacket publishPacket = mock(PublishPacket.class);

        when(input.getConnectionInformation()).thenReturn(connectionInformation);
        when(connectionInformation.getConnectionAttributeStore()).thenReturn(attributes);
        when(input.getClientInformation()).thenReturn(clientInformation);
        when(clientInformation.getClientId()).thenReturn("subscriber-1");
        when(input.getPublishPacket()).thenReturn(publishPacket);
        when(publishPacket.getTopic()).thenReturn("sensors/kitchen/temperature");
        when(output.async(any(), any())).thenReturn(async);
        doAnswer(invocation -> {
                    invocation.<Runnable>getArgument(0).run();
                    return CompletableFuture.completedFuture(null);
                })
                .when(executorService)
                .submit(any(Runnable.class));

        authorizer = new OutboundReadAuthorizer(authService, executorService, Duration.ofSeconds(2));
    }

    @Test
    void deliversPublishWhenReadAclAllowsTopic() {
        principal();
        when(authService.authorize(
                        new AuthenticatedPrincipal("alice", false),
                        MqttActivity.SUBSCRIBE,
                        "sensors/kitchen/temperature"))
                .thenReturn(true);

        authorizer.onOutboundPublish(input, output);

        verify(output, never()).preventPublishDelivery();
        verify(async).resume();
    }

    @Test
    void completesCachedReadDecisionWithoutUsingTheManagedExecutor() {
        principal();
        when(authService.authorizeFromCache(
                        new AuthenticatedPrincipal("alice", false),
                        MqttActivity.SUBSCRIBE,
                        "sensors/kitchen/temperature"))
                .thenReturn(Optional.of(true));

        authorizer.onOutboundPublish(input, output);

        verify(output, never()).preventPublishDelivery();
        verify(output, never()).async(any(), any());
        verify(executorService, never()).submit(any(Runnable.class));
        verify(authService, never()).authorize(any(), any(), any());

        final PublishOutboundOutput deniedOutput = mock(PublishOutboundOutput.class);
        when(authService.authorizeFromCache(
                        new AuthenticatedPrincipal("alice", false),
                        MqttActivity.SUBSCRIBE,
                        "sensors/kitchen/temperature"))
                .thenReturn(Optional.of(false));

        authorizer.onOutboundPublish(input, deniedOutput);

        verify(deniedOutput).preventPublishDelivery();
        verify(deniedOutput, never()).async(any(), any());
    }

    @Test
    void preventsDeliveryWhenReadAclDeniesTopicOrBackendFails() {
        principal();
        authorizer.onOutboundPublish(input, output);
        verify(output).preventPublishDelivery();
        verify(async).resume();

        final PublishOutboundOutput failingOutput = mock(PublishOutboundOutput.class);
        @SuppressWarnings("unchecked")
        final Async<PublishOutboundOutput> failingAsync = (Async<PublishOutboundOutput>) mock(Async.class);
        when(failingOutput.async(any(), any())).thenReturn(failingAsync);
        when(authService.authorize(any(), eq(MqttActivity.SUBSCRIBE), any()))
                .thenThrow(new IllegalStateException("database unavailable"));
        authorizer.onOutboundPublish(input, failingOutput);
        verify(failingOutput).preventPublishDelivery();
        verify(failingAsync).resume();
    }

    @Test
    void preventsDeliveryImmediatelyWithoutAuthenticatedPrincipal() {
        when(attributes.getAsString("eddie.mqtt.auth.username")).thenReturn(Optional.empty());

        authorizer.onOutboundPublish(input, output);

        verify(output).preventPublishDelivery();
        verify(output, never()).async(any(), any());
        verify(authService, never()).authorize(any(), any(), any());
    }

    @Test
    void preventsDeliveryWhenExecutorRejectsTask() {
        principal();
        doThrow(new RejectedExecutionException("stopping"))
                .when(executorService)
                .submit(any(Runnable.class));

        authorizer.onOutboundPublish(input, output);

        verify(output).preventPublishDelivery();
        verify(async).resume();
    }

    private void principal() {
        when(attributes.getAsString("eddie.mqtt.auth.username")).thenReturn(Optional.of("alice"));
        when(attributes.getAsString("eddie.mqtt.auth.local-superuser")).thenReturn(Optional.of("false"));
    }
}
