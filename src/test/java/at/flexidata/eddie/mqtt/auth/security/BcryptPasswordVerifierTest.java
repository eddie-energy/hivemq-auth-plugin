package at.flexidata.eddie.mqtt.auth.security;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import at.favre.lib.crypto.bcrypt.BCrypt;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class BcryptPasswordVerifierTest {

    private final BcryptPasswordVerifier verifier = new BcryptPasswordVerifier();

    @Test
    void verifiesBcryptPassword() {
        final String password = "correct horse";
        final byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8);
        final String hash = BCrypt.withDefaults().hashToString(4, password.toCharArray());

        assertTrue(verifier.matches(passwordBytes, hash));
        assertTrue(verifier.matches(passwordBytes, "$2a$" + hash.substring(4)));
        assertTrue(verifier.matches(passwordBytes, "$2b$" + hash.substring(4)));
        assertTrue(verifier.matches(passwordBytes, "$2y$" + hash.substring(4)));
        assertFalse(verifier.matches("wrong battery".getBytes(StandardCharsets.UTF_8), hash));
    }

    @Test
    void rejectsMalformedHash() {
        assertFalse(verifier.matches("password".getBytes(StandardCharsets.UTF_8), "not-a-bcrypt-hash"));
    }
}
