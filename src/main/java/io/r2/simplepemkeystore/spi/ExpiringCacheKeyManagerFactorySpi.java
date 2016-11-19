package io.r2.simplepemkeystore.spi;

import io.r2.simplepemkeystore.ExpiringCacheKeyManagerParameters;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactorySpi;
import javax.net.ssl.ManagerFactoryParameters;
import java.security.*;

/**
 * A key manager factory with an expiring internal cache, so keys can be reloaded
 * The main worker class is in ExpiringCacheKeyManager, this is just a wrapper
 */
public class ExpiringCacheKeyManagerFactorySpi extends KeyManagerFactorySpi {

    protected KeyManager keyManager = null;

    @Override
    protected void engineInit(KeyStore keyStore, char[] password) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        keyManager = new ExpiringCacheKeyManager(
                ExpiringCacheKeyManagerParameters.forKeyStore(keyStore, password)
        );
    }

    /**
     * Initializes key manager with a special parameter object, which may contain revalidation time
     *
     * @param params must be instance of ExpiringCacheKeyManagerParameters
     * @throws InvalidAlgorithmParameterException if params is not correct type
     */
    @Override
    protected void engineInit(ManagerFactoryParameters params) throws InvalidAlgorithmParameterException {
        if (params instanceof ExpiringCacheKeyManagerParameters == false)
            throw new InvalidAlgorithmParameterException("Parameters must be instance of ExpiringCacheKeyManagerParameters");
        ExpiringCacheKeyManagerParameters inParams = (ExpiringCacheKeyManagerParameters)params;
        if (inParams.getCacheRevalidation() < 5)
            throw new InvalidAlgorithmParameterException("Cache expiration time must be at least 5 seconds");
        try {
            keyManager = new ExpiringCacheKeyManager(inParams);
        }
        catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            throw new InvalidAlgorithmParameterException(e);
        }
    }

    @Override
    protected KeyManager[] engineGetKeyManagers() {
        if (keyManager == null) throw new IllegalStateException("Not initialized");
        return new KeyManager[] { keyManager };
    }
}
