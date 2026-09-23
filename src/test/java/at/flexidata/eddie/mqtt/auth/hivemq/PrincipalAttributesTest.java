package at.flexidata.eddie.mqtt.auth.hivemq;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import at.flexidata.eddie.mqtt.auth.security.AuthenticatedPrincipal;
import com.hivemq.extension.sdk.api.client.parameter.ConnectionAttributeStore;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class PrincipalAttributesTest {

    @Test
    void storesAndReadsPrincipal() {
        final ConnectionAttributeStore attributes = mock(ConnectionAttributeStore.class);
        final AuthenticatedPrincipal principal = new AuthenticatedPrincipal("alice", true);
        when(attributes.getAsString("eddie.mqtt.auth.username")).thenReturn(Optional.of("alice"));
        when(attributes.getAsString("eddie.mqtt.auth.local-superuser")).thenReturn(Optional.of("true"));

        PrincipalAttributes.put(attributes, principal);
        final Optional<AuthenticatedPrincipal> restored = PrincipalAttributes.get(attributes);

        verify(attributes).putAsString("eddie.mqtt.auth.username", "alice");
        verify(attributes).putAsString("eddie.mqtt.auth.local-superuser", "true");
        assertEquals(principal, restored.orElseThrow());
    }

    @Test
    void returnsEmptyWithoutUsernameAndDefaultsRoleToDatabaseUser() {
        final ConnectionAttributeStore attributes = mock(ConnectionAttributeStore.class);
        when(attributes.getAsString("eddie.mqtt.auth.username")).thenReturn(Optional.empty());
        assertTrue(PrincipalAttributes.get(attributes).isEmpty());

        when(attributes.getAsString("eddie.mqtt.auth.username")).thenReturn(Optional.of("alice"));
        when(attributes.getAsString("eddie.mqtt.auth.local-superuser")).thenReturn(Optional.empty());
        assertFalse(PrincipalAttributes.get(attributes).orElseThrow().localSuperuser());
    }
}
