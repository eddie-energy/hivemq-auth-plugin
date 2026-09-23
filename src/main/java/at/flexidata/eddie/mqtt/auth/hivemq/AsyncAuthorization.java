package at.flexidata.eddie.mqtt.auth.hivemq;

import com.hivemq.extension.sdk.api.async.Async;
import com.hivemq.extension.sdk.api.services.ManagedExtensionExecutorService;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

final class AsyncAuthorization {

    private AsyncAuthorization() {}

    static <T> void submit(
            final ManagedExtensionExecutorService executorService,
            final BooleanSupplier decision,
            final Runnable success,
            final Runnable failure,
            final Async<T> async,
            final Consumer<RuntimeException> errorHandler) {
        try {
            executorService.submit(() -> evaluate(decision, success, failure, async, errorHandler));
        } catch (RuntimeException exception) {
            errorHandler.accept(exception);
            complete(failure, async);
        }
    }

    private static <T> void evaluate(
            final BooleanSupplier decision,
            final Runnable success,
            final Runnable failure,
            final Async<T> async,
            final Consumer<RuntimeException> errorHandler) {
        boolean authorized = false;
        try {
            authorized = decision.getAsBoolean();
        } catch (RuntimeException exception) {
            errorHandler.accept(exception);
        }
        complete(authorized ? success : failure, async);
    }

    private static <T> void complete(final Runnable outcome, final Async<T> async) {
        try {
            outcome.run();
        } finally {
            async.resume();
        }
    }
}
