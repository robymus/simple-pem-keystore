package io.r2.simplepemkeystore;

import javax.net.ssl.ManagerFactoryParameters;
import java.security.KeyStore;

/**
 * Parameters builder for the ExpiringCacheKeyManagerFactory.
 */
public class ExpiringCacheKeyManagerParameters implements ManagerFactoryParameters {

    /** Default cache expiration in seconds, one hour */
    public static final long DEFAULT_CACHE_EXPIRATION = 3600;

    private KeyStore keyStore;
    private char[] password;
    private long cacheRevalidation;

    /**
     * Create without password
     *
     * @param keyStore the keyStore to use
     */
    public ExpiringCacheKeyManagerParameters(KeyStore keyStore) {
        this(keyStore, new char[0]);
    }

    /**
     * Create without password
     *
     * @param keyStore the keyStore to use
     * @param password the keystore password
     */
    public ExpiringCacheKeyManagerParameters(KeyStore keyStore, char[] password) {
        this.keyStore = keyStore;
        this.password = password;
        this.cacheRevalidation = DEFAULT_CACHE_EXPIRATION;
    }

    /**
     * Sets keystore password
     *
     * @param password the KeyStore password to use
     * @return the object itself for chaining
     */
    public ExpiringCacheKeyManagerParameters withPassword(char[] password) {
        this.password = password;
        return this;
    }


    /**
     * Sets cache revalidation time.
     * Note: revalidation time must be at least 5 seconds (for sanity)
     *
     * @param revalidation cache revalidation in seconds
     * @return the object itself for chaining
     */
    public ExpiringCacheKeyManagerParameters withRevalidation(long revalidation) {
        cacheRevalidation = revalidation;
        return this;
    }

    /**
     * @return the KeyStore to use
     */
    public KeyStore getKeyStore() {
        return keyStore;
    }

    /**
     * @return password to use for the keyStore
     */
    public char[] getPassword() {
        return password;
    }

    /**
     * @return cache expiration in milliseconds
     */
    public long getCacheRevalidation() {
        return cacheRevalidation;
    }

    /**
     * Convenience factory method without keystore password
     * @param keyStore the KeyStore to use
     *
     * @return new instance with default expiration and no keystore password
     */
    public static ExpiringCacheKeyManagerParameters forKeyStore(KeyStore keyStore) {
        return new ExpiringCacheKeyManagerParameters(keyStore);
    }

    /**
     * Convenience factory method
     *
     * @param keyStore the KeyStore to use
     * @param password the KeyStore password
     * @return new instance with default expiration
     */
    public static ExpiringCacheKeyManagerParameters forKeyStore(KeyStore keyStore, char[] password) {
        return new ExpiringCacheKeyManagerParameters(keyStore, password);
    }

}
