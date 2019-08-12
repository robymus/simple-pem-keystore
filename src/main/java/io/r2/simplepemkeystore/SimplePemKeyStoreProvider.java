package io.r2.simplepemkeystore;

import java.security.Provider;
import java.security.Security;

/**
 * Entry point for JCE integration, defining implemented functions.
 */
public final class SimplePemKeyStoreProvider extends Provider {

    public SimplePemKeyStoreProvider() {
        super(
                "SimplePemKeyStore",
                0.2,
                "SimplePemKeyStore 0.2 - PEM based key stores with automatic reloading"
        );
        put("KeyStore.simplepem", "io.r2.simplepemkeystore.spi.SimplePemKeyStoreSpi");
        put("KeyStore.simplepemreload", "io.r2.simplepemkeystore.spi.ReloadablePemKeyStoreSpi");
        put("KeyManagerFactory.simplepemreload", "io.r2.simplepemkeystore.spi.ExpiringCacheKeyManagerFactorySpi");
    }

    /**
     * Static helper to register SimplePemKeyStore as security provider
     */
    public static void register() {
        Security.addProvider(new SimplePemKeyStoreProvider());
    }

}
