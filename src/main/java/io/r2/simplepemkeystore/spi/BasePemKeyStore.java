package io.r2.simplepemkeystore.spi;

import java.io.IOException;
import java.io.OutputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Abstract class implementing the boilerplate methods of a KeyStore engine
 * It will work from a map of PemCertKey objects, indexed by alias
 * Subclasses should take care of populating and updating this underlying structure
 */
abstract class BasePemKeyStore extends KeyStoreSpi {

    protected Map<String, PemCertKey> store;

    public BasePemKeyStore() {
        store = new ConcurrentHashMap<>();
    }

    @Override
    public Key engineGetKey(String alias, char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException {
        PemCertKey certKey = store.get(alias);
        if (certKey == null) return null;
        return certKey.getPrivateKey();
    }

    @Override
    public Certificate[] engineGetCertificateChain(String alias) {
        PemCertKey certKey = store.get(alias);
        if (certKey == null) return null;
        return certKey.getCertificateChain();
    }

    @Override
    public Certificate engineGetCertificate(String alias) {
        PemCertKey certKey = store.get(alias);
        if (certKey == null) return null;
        return certKey.getCertificate();
    }

    @Override
    public Date engineGetCreationDate(String alias) {
        PemCertKey certKey = store.get(alias);
        if (certKey == null) return null;
        return certKey.getCreationDate();
    }

    @Override
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) throws KeyStoreException {
        throw new KeyStoreException("Operation not implemented");
    }

    @Override
    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) throws KeyStoreException {
        throw new KeyStoreException("Operation not implemented");
    }

    @Override
    public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException {
        throw new KeyStoreException("Operation not implemented");
    }

    @Override
    public void engineDeleteEntry(String alias) throws KeyStoreException {
        throw new KeyStoreException("Operation not implemented");
    }

    @Override
    public Enumeration<String> engineAliases() {
        return Collections.enumeration(store.keySet());
    }

    @Override
    public boolean engineContainsAlias(String alias) {
        return store.containsKey(alias);
    }

    @Override
    public int engineSize() {
        return store.size();
    }

    @Override
    public boolean engineIsKeyEntry(String alias) {
        PemCertKey certKey = store.get(alias);
        if (certKey == null) return false;
        return certKey.hasKey();
    }

    @Override
    public boolean engineIsCertificateEntry(String alias) {
        PemCertKey certKey = store.get(alias);
        if (certKey == null) return false;
        return certKey.hasCertificate();
    }

    @Override
    public String engineGetCertificateAlias(Certificate cert) {
        return store.entrySet().stream()
                .filter((e) -> e.getValue().matchesCertificate(cert))
                .map(Map.Entry::getKey)
                .findFirst()
                .orElse(null);
    }

    @Override
    public void engineStore(OutputStream stream, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException {
        throw new CertificateException("Store not supported");
    }

}
