package at.flexidata.eddie.mqtt.auth.repository;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class PostgresAuthRepositoryTest {

    @Test
    void convertsCommonDatabaseBooleanRepresentations() {
        assertTrue(PostgresAuthRepository.asBoolean(true));
        assertTrue(PostgresAuthRepository.asBoolean(1));
        assertTrue(PostgresAuthRepository.asBoolean("YES"));
        assertTrue(PostgresAuthRepository.asBoolean("t"));
        assertFalse(PostgresAuthRepository.asBoolean(false));
        assertFalse(PostgresAuthRepository.asBoolean(0L));
        assertFalse(PostgresAuthRepository.asBoolean("no"));
        assertFalse(PostgresAuthRepository.asBoolean(null));
        assertFalse(PostgresAuthRepository.asBoolean(new Object()));
    }
}
