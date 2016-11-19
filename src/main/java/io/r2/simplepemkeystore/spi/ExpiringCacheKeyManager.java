package io.r2.simplepemkeystore.spi;

import io.r2.simplepemkeystore.ExpiringCacheKeyManagerParameters;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.security.auth.x500.X500Principal;
import java.net.Socket;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * A key manager with an expiring cache
 * Based on sun.security.ssl.SunX509KeyManagerImpl, but the static certificate cache has been
 * replaced with a cache that is revalidated over time.
 *
 * After the specified revalidation time all creation dates are checked in the key store, and if they are
 * newer than the stored one, it is rebuilt in the cache.
 */
public class ExpiringCacheKeyManager extends X509ExtendedKeyManager {

    private static final String[] STRING0 = new String[0];

    /** The current cache revalidation time */
    private long cacheRevalidation;
    /** The underlying keystore */
    private KeyStore keyStore;
    /** Password for the underlying keystore */
    private char[] keyStorePassword;

    /** scheduler for the cache refreshing task */
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);

    /*
     * The credentials from the KeyStore as
     * Map: String(alias) -> X509Credentials(credentials)
     */
    private Map<String,X509Credentials> credentialsMap;

    /*
     * Cached server aliases for the case issuers == null.
     * (in the current JSSE implementation, issuers are always null for
     * server certs). See chooseServerAlias() for details.
     *
     * Map: String(keyType) -> String[](alias)
     */
    private final Map<String,String[]> serverAliasCache;

    /*
     * Basic container for credentials implemented as an inner class.
     */
    private static class X509Credentials {
        PrivateKey privateKey;
        X509Certificate[] certificates;
        private Set<X500Principal> issuerX500Principals;
        Date creationDate;

        X509Credentials(PrivateKey privateKey, X509Certificate[] certificates, Date creationDate) {
            // assert privateKey and certificates != null
            this.privateKey = privateKey;
            this.certificates = certificates;
            this.creationDate = creationDate;
        }

        synchronized Set<X500Principal> getIssuerX500Principals() {
            // lazy initialization
            if (issuerX500Principals == null) {
                issuerX500Principals = new HashSet<X500Principal>();
                for (int i = 0; i < certificates.length; i++) {
                    issuerX500Principals.add(
                            certificates[i].getIssuerX500Principal());
                }
            }
            return issuerX500Principals;
        }
    }

    ExpiringCacheKeyManager(ExpiringCacheKeyManagerParameters params)
            throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {

        cacheRevalidation = params.getCacheRevalidation();
        keyStore = params.getKeyStore();
        keyStorePassword = params.getPassword();

        serverAliasCache = Collections.synchronizedMap(new HashMap<String,String[]>());

        buildCache();

        // set up a scheduled task for cache rebuilding
        if (keyStore != null) scheduler.scheduleAtFixedRate(()->{
            try {
                revalidateCache();
           }
            catch (Exception e) {
                // cache rebuild failed, keep the old one quietly
            }
        }, cacheRevalidation, cacheRevalidation, TimeUnit.SECONDS);
    }


    /**
     * Builds the cache (called at startup)
     */
    private void buildCache() throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {

        credentialsMap = new HashMap<String,X509Credentials>();
        if (keyStore == null) {
            return;
        }

        for (Enumeration<String> aliases = keyStore.aliases(); aliases.hasMoreElements(); ) {
            String alias = aliases.nextElement();
            revalidateAlias(alias);
        }
    }

    /**
     * Revalidate the cache (called as a scheduled task)
     */
    private void revalidateCache() throws KeyStoreException {

        for (Enumeration<String> aliases = keyStore.aliases(); aliases.hasMoreElements(); ) {
            String alias = aliases.nextElement();
            try {
                X509Credentials cred = credentialsMap.get(alias);
                if (cred == null || cred.creationDate.before(keyStore.getCreationDate(alias))) {
                    revalidateAlias(alias);
                }
            }
            catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
                // erro updating alias, ignore this one
            }
        }
    }


    /**
     * Rechecks alias validity, removes from cache if invalid, adds to cache (replaces) if valid
     * @param alias the alias to check
     */
    private void revalidateAlias(String alias)
            throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        if (!keyStore.isKeyEntry(alias)) {
            credentialsMap.remove(alias);
            return;
        }
        Key key = keyStore.getKey(alias, keyStorePassword);
        if (key instanceof PrivateKey == false) {
            credentialsMap.remove(alias);
            return;
        }
        Certificate[] certs = keyStore.getCertificateChain(alias);
        if ((certs == null) || (certs.length == 0) || !(certs[0] instanceof X509Certificate)) {
            credentialsMap.remove(alias);
            return;
        }
        if (!(certs instanceof X509Certificate[])) {
            Certificate[] tmp = new X509Certificate[certs.length];
            System.arraycopy(certs, 0, tmp, 0, certs.length);
            certs = tmp;
        }

        Date creationDate = keyStore.getCreationDate(alias);

        X509Credentials cred = new X509Credentials((PrivateKey)key, (X509Certificate[])certs, creationDate);
        credentialsMap.put(alias, cred);
    }

    /*
     * Returns the certificate chain associated with the given alias.
     *
     * @return the certificate chain (ordered with the user's certificate first
     * and the root certificate authority last)
     */
    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        if (alias == null) {
            return null;
        }
        X509Credentials cred = credentialsMap.get(alias);
        if (cred == null) {
            return null;
        } else {
            return cred.certificates.clone();
        }
    }

    /*
     * Returns the key associated with the given alias
     */
    @Override
    public PrivateKey getPrivateKey(String alias) {
        if (alias == null) {
            return null;
        }
        X509Credentials cred = credentialsMap.get(alias);
        if (cred == null) {
            return null;
        } else {
            return cred.privateKey;
        }
    }

    /*
     * Choose an alias to authenticate the client side of a secure
     * socket given the public key type and the list of
     * certificate issuer authorities recognized by the peer (if any).
     */
    @Override
    public String chooseClientAlias(String[] keyTypes, Principal[] issuers, Socket socket) {
        /*
         * We currently don't do anything with socket, but
         * someday we might.  It might be a useful hint for
         * selecting one of the aliases we get back from
         * getClientAliases().
         */

        if (keyTypes == null) {
            return null;
        }

        for (int i = 0; i < keyTypes.length; i++) {
            String[] aliases = getClientAliases(keyTypes[i], issuers);
            if ((aliases != null) && (aliases.length > 0)) {
                return aliases[0];
            }
        }
        return null;
    }

    /*
     * Choose an alias to authenticate the client side of an
     * <code>SSLEngine</code> connection given the public key type
     * and the list of certificate issuer authorities recognized by
     * the peer (if any).
     *
     * @since 1.5
     */
    @Override
    public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, SSLEngine engine) {
        /*
         * If we ever start using socket as a selection criteria,
         * we'll need to adjust this.
         */
        return chooseClientAlias(keyType, issuers, null);
    }

    /*
     * Choose an alias to authenticate the server side of a secure
     * socket given the public key type and the list of
     * certificate issuer authorities recognized by the peer (if any).
     */
    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        /*
         * We currently don't do anything with socket, but
         * someday we might.  It might be a useful hint for
         * selecting one of the aliases we get back from
         * getServerAliases().
         */
        if (keyType == null) {
            return null;
        }

        String[] aliases;

        if (issuers == null || issuers.length == 0) {
            aliases = serverAliasCache.get(keyType);
            if (aliases == null) {
                aliases = getServerAliases(keyType, issuers);
                // Cache the result (positive and negative lookups)
                if (aliases == null) {
                    aliases = STRING0;
                }
                serverAliasCache.put(keyType, aliases);
            }
        } else {
            aliases = getServerAliases(keyType, issuers);
        }
        if ((aliases != null) && (aliases.length > 0)) {
            return aliases[0];
        }
        return null;
    }

    /*
     * Choose an alias to authenticate the server side of an
     * <code>SSLEngine</code> connection given the public key type
     * and the list of certificate issuer authorities recognized by
     * the peer (if any).
     *
     * @since 1.5
     */
    @Override
    public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
        /*
         * If we ever start using socket as a selection criteria,
         * we'll need to adjust this.
         */
        return chooseServerAlias(keyType, issuers, null);
    }

    /*
     * Get the matching aliases for authenticating the client side of a secure
     * socket given the public key type and the list of
     * certificate issuer authorities recognized by the peer (if any).
     */
    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        return getAliases(keyType, issuers);
    }

    /*
     * Get the matching aliases for authenticating the server side of a secure
     * socket given the public key type and the list of
     * certificate issuer authorities recognized by the peer (if any).
     */
    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return getAliases(keyType, issuers);
    }

    /*
     * Get the matching aliases for authenticating the either side of a secure
     * socket given the public key type and the list of
     * certificate issuer authorities recognized by the peer (if any).
     *
     * Issuers comes to us in the form of X500Principal[].
     */
    private String[] getAliases(String keyType, Principal[] issuers) {
        if (keyType == null) {
            return null;
        }
        if (issuers == null) {
            issuers = new X500Principal[0];
        }
        if (issuers instanceof X500Principal[] == false) {
            // normally, this will never happen but try to recover if it does
            issuers = convertPrincipals(issuers);
        }
        String sigType;
        if (keyType.contains("_")) {
            int k = keyType.indexOf("_");
            sigType = keyType.substring(k + 1);
            keyType = keyType.substring(0, k);
        } else {
            sigType = null;
        }

        X500Principal[] x500Issuers = (X500Principal[])issuers;
        // the algorithm below does not produce duplicates, so avoid Set
        List<String> aliases = new ArrayList<>();

        for (Map.Entry<String,X509Credentials> entry :
                credentialsMap.entrySet()) {

            String alias = entry.getKey();
            X509Credentials credentials = entry.getValue();
            X509Certificate[] certs = credentials.certificates;

            if (!keyType.equals(certs[0].getPublicKey().getAlgorithm())) {
                continue;
            }
            if (sigType != null) {
                if (certs.length > 1) {
                    // if possible, check the public key in the issuer cert
                    if (!sigType.equals(
                            certs[1].getPublicKey().getAlgorithm())) {
                        continue;
                    }
                } else {
                    // Check the signature algorithm of the certificate itself.
                    // Look for the "withRSA" in "SHA1withRSA", etc.
                    String sigAlgName =
                            certs[0].getSigAlgName().toUpperCase(Locale.ENGLISH);
                    String pattern = "WITH" +
                            sigType.toUpperCase(Locale.ENGLISH);
                    if (sigAlgName.contains(pattern) == false) {
                        continue;
                    }
                }
            }

            if (issuers.length == 0) {
                // no issuer specified, match all
                aliases.add(alias);
            } else {
                Set<X500Principal> certIssuers =
                        credentials.getIssuerX500Principals();
                for (int i = 0; i < x500Issuers.length; i++) {
                    if (certIssuers.contains(issuers[i])) {
                        aliases.add(alias);
                        break;
                    }
                }
            }
        }

        String[] aliasStrings = aliases.toArray(STRING0);
        return ((aliasStrings.length == 0) ? null : aliasStrings);
    }

    /*
     * Convert an array of Principals to an array of X500Principals, if
     * possible. Principals that cannot be converted are ignored.
     */
    private static X500Principal[] convertPrincipals(Principal[] principals) {
        List<X500Principal> list = new ArrayList<>(principals.length);
        for (int i = 0; i < principals.length; i++) {
            Principal p = principals[i];
            if (p instanceof X500Principal) {
                list.add((X500Principal)p);
            } else {
                try {
                    list.add(new X500Principal(p.getName()));
                } catch (IllegalArgumentException e) {
                    // ignore
                }
            }
        }
        return list.toArray(new X500Principal[list.size()]);
    }

}
