package at.flexidata.eddie.mqtt.auth.security;

import at.favre.lib.crypto.bcrypt.BCrypt;
import java.nio.charset.StandardCharsets;

/** Password verifier for bcrypt hashes, including the {@code $2a$}, {@code $2b$}, and {@code $2y$} forms. */
public final class BcryptPasswordVerifier implements PasswordVerifier {

    /** Creates a bcrypt password verifier. */
    public BcryptPasswordVerifier() {
        // The verifier is stateless and requires no initialization.
    }

    /** {@inheritDoc} */
    @Override
    public boolean matches(final byte[] password, final String encodedPassword) {
        try {
            return BCrypt.verifyer()
                    .verify(password, encodedPassword.getBytes(StandardCharsets.UTF_8))
                    .verified;
        } catch (IllegalArgumentException exception) {
            return false;
        }
    }
}
