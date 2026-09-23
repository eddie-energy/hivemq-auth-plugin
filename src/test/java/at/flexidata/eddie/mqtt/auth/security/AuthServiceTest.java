package at.flexidata.eddie.mqtt.auth.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import at.flexidata.eddie.mqtt.auth.TestConfigs;
import at.flexidata.eddie.mqtt.auth.repository.AuthRepository;
import at.flexidata.eddie.mqtt.auth.repository.AuthorizationRules;
import at.flexidata.eddie.mqtt.auth.repository.RepositoryException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class AuthServiceTest {

    private static final byte[] DATABASE_PASSWORD = "database-secret".getBytes(StandardCharsets.UTF_8);

    @Test
    void authenticatesReservedLocalSuperuserWithoutDatabaseLookup() {
        final AuthRepository repository = mock(AuthRepository.class);
        final PasswordVerifier passwordVerifier = mock(PasswordVerifier.class);
        try (AuthService service =
                new AuthService(repository, passwordVerifier, TestConfigs.config(true, true, 1024))) {
            final Optional<AuthenticatedPrincipal> principal =
                    service.authenticate("eddie", "local-secret".getBytes(StandardCharsets.UTF_8));

            assertTrue(principal.isPresent());
            assertTrue(principal.orElseThrow().localSuperuser());
            assertFalse(service.authenticate("eddie", DATABASE_PASSWORD).isPresent());
            verify(repository, never()).findPasswordHash(anyString());
        }
    }

    @Test
    void authenticatesDatabasePasswordAndCachesOnlyHashLookup() {
        final AuthRepository repository = mock(AuthRepository.class);
        final PasswordVerifier passwordVerifier = mock(PasswordVerifier.class);
        when(repository.findPasswordHash("alice")).thenReturn(Optional.of("encoded"));
        when(passwordVerifier.matches(DATABASE_PASSWORD, "encoded")).thenReturn(true);

        try (AuthService service =
                new AuthService(repository, passwordVerifier, TestConfigs.config(true, false, 1024))) {
            assertTrue(service.authenticate("alice", DATABASE_PASSWORD).isPresent());
            assertTrue(service.authenticate("alice", DATABASE_PASSWORD).isPresent());

            verify(repository).findPasswordHash("alice");
            verify(passwordVerifier, times(2)).matches(DATABASE_PASSWORD, "encoded");
        }
    }

    @Test
    void cachesMissingUserAndBypassesCacheWhenDisabled() {
        final AuthRepository repository = mock(AuthRepository.class);
        when(repository.findPasswordHash("unknown")).thenReturn(Optional.empty());

        try (AuthService cached =
                new AuthService(repository, (password, hash) -> false, TestConfigs.config(true, false, 1024))) {
            assertFalse(cached.authenticate("unknown", DATABASE_PASSWORD).isPresent());
            assertFalse(cached.authenticate("unknown", DATABASE_PASSWORD).isPresent());
            verify(repository).findPasswordHash("unknown");
        }

        final AuthRepository uncachedRepository = mock(AuthRepository.class);
        when(uncachedRepository.findPasswordHash("unknown")).thenReturn(Optional.empty());
        try (AuthService uncached = new AuthService(
                uncachedRepository, (password, hash) -> false, TestConfigs.config(false, false, 1024))) {
            assertFalse(uncached.authenticate("unknown", DATABASE_PASSWORD).isPresent());
            assertFalse(uncached.authenticate("unknown", DATABASE_PASSWORD).isPresent());
            verify(uncachedRepository, times(2)).findPasswordHash("unknown");
        }
    }

    @Test
    void rejectsCredentialsAboveConfiguredLimits() {
        final AuthRepository repository = mock(AuthRepository.class);
        try (AuthService service =
                new AuthService(repository, (password, hash) -> true, TestConfigs.config(true, false, 4))) {
            assertFalse(service.credentialsWithinLimits("alice", 4));
            assertFalse(service.credentialsWithinLimits("bob", 5));
            assertFalse(service.credentialsWithinLimits("ééé", 1));
            assertFalse(service.authenticate("alice", new byte[] {1}).isPresent());
            verify(repository, never()).findPasswordHash(anyString());
        }
    }

    @Test
    void authorizesLocalAndDatabaseSuperusersForEveryTopic() {
        final AuthRepository repository = mock(AuthRepository.class);
        when(repository.findAuthorization("admin", MqttActivity.PUBLISH))
                .thenReturn(AuthorizationRules.superuserRules());
        try (AuthService service =
                new AuthService(repository, (password, hash) -> false, TestConfigs.config(true, true, 1024))) {
            assertTrue(service.authorize(
                    new AuthenticatedPrincipal("eddie", true), MqttActivity.PUBLISH, "$SYS/private"));
            assertTrue(service.authorize(
                    new AuthenticatedPrincipal("admin", false), MqttActivity.PUBLISH, "$SYS/private"));
            verify(repository, never()).findAuthorization("eddie", MqttActivity.PUBLISH);
        }
    }

    @Test
    void authorizesPublishAndSubscribeUsingCachedAclRules() {
        final AuthRepository repository = mock(AuthRepository.class);
        when(repository.findAuthorization("alice", MqttActivity.PUBLISH))
                .thenReturn(new AuthorizationRules(false, List.of("sensors/#")));
        when(repository.findAuthorization("alice", MqttActivity.SUBSCRIBE))
                .thenReturn(new AuthorizationRules(false, List.of("events/+/status")));
        final AuthenticatedPrincipal alice = new AuthenticatedPrincipal("alice", false);

        try (AuthService service =
                new AuthService(repository, (password, hash) -> false, TestConfigs.config(true, false, 1024))) {
            assertEquals(
                    Optional.empty(),
                    service.authorizeFromCache(alice, MqttActivity.PUBLISH, "sensors/kitchen"));
            assertTrue(service.authorize(alice, MqttActivity.PUBLISH, "sensors/kitchen"));
            assertFalse(service.authorize(alice, MqttActivity.PUBLISH, "private/data"));
            assertTrue(service.authorize(alice, MqttActivity.SUBSCRIBE, "events/device/status"));
            assertFalse(service.authorize(alice, MqttActivity.SUBSCRIBE, "events/#"));
            assertEquals(
                    Optional.of(true),
                    service.authorizeFromCache(alice, MqttActivity.PUBLISH, "sensors/kitchen"));
            assertEquals(
                    Optional.of(false),
                    service.authorizeFromCache(alice, MqttActivity.PUBLISH, "private/data"));
            verify(repository).findAuthorization("alice", MqttActivity.PUBLISH);
            verify(repository).findAuthorization("alice", MqttActivity.SUBSCRIBE);
        }
    }

    @Test
    void cachedAuthorizationHandlesLocalSuperuserAndDisabledCacheWithoutDatabaseAccess() {
        final AuthRepository repository = mock(AuthRepository.class);
        final AuthenticatedPrincipal localSuperuser = new AuthenticatedPrincipal("eddie", true);
        final AuthenticatedPrincipal alice = new AuthenticatedPrincipal("alice", false);

        try (AuthService service =
                new AuthService(repository, (password, hash) -> false, TestConfigs.config(false, true, 1024))) {
            assertEquals(
                    Optional.of(true),
                    service.authorizeFromCache(localSuperuser, MqttActivity.PUBLISH, "any/topic"));
            assertEquals(
                    Optional.empty(),
                    service.authorizeFromCache(alice, MqttActivity.PUBLISH, "any/topic"));
            verify(repository, never()).findAuthorization(anyString(), any());
        }
    }

    @Test
    void invalidatingCachesForcesFreshLookupAndRepositoryErrorsPropagate() {
        final AuthRepository repository = mock(AuthRepository.class);
        when(repository.findAuthorization("alice", MqttActivity.PUBLISH))
                .thenReturn(new AuthorizationRules(false, List.of("allowed/#")));
        final AuthenticatedPrincipal alice = new AuthenticatedPrincipal("alice", false);

        try (AuthService service =
                new AuthService(repository, (password, hash) -> false, TestConfigs.config(true, false, 1024))) {
            assertTrue(service.authorize(alice, MqttActivity.PUBLISH, "allowed/topic"));
            service.invalidateCaches();
            assertTrue(service.authorize(alice, MqttActivity.PUBLISH, "allowed/topic"));
            verify(repository, times(2)).findAuthorization("alice", MqttActivity.PUBLISH);
        }

        final AuthRepository failingRepository = mock(AuthRepository.class);
        when(failingRepository.findAuthorization(anyString(), any()))
                .thenThrow(new RepositoryException("failure", new IllegalStateException()));
        try (AuthService service = new AuthService(
                failingRepository, (password, hash) -> false, TestConfigs.config(true, false, 1024))) {
            assertThrows(
                    RepositoryException.class,
                    () -> service.authorize(alice, MqttActivity.PUBLISH, "allowed/topic"));
        }
    }

    @Test
    void deniesPasswordMismatchAndNullAuthorizationRules() {
        final AuthRepository repository = mock(AuthRepository.class);
        when(repository.findPasswordHash("alice")).thenReturn(Optional.of("encoded"));
        when(repository.findAuthorization("alice", MqttActivity.PUBLISH)).thenReturn(null);
        final AuthenticatedPrincipal alice = new AuthenticatedPrincipal("alice", false);

        try (AuthService service =
                new AuthService(repository, (password, hash) -> false, TestConfigs.config(false, false, 1024))) {
            assertFalse(service.authenticate("alice", DATABASE_PASSWORD).isPresent());
            assertFalse(service.authorize(alice, MqttActivity.PUBLISH, "sensors/kitchen"));
        }
    }
}
