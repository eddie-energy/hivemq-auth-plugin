package at.flexidata.eddie.mqtt.auth.repository;

import java.io.Serial;

/** Signals a database or connection-pool failure without exposing credentials in its message. */
public final class RepositoryException extends RuntimeException {

    @Serial
    private static final long serialVersionUID = 1L;

    /**
     * Creates a repository failure.
     *
     * @param message operation-specific, credential-free description
     * @param cause underlying failure
     */
    public RepositoryException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
