package io.r2.simplepemkeystore.spi;

import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

/**
 * A simple (non-reloadable) PEM based key store
 */
public class SimplePemKeyStoreSpi extends BasePemKeyStore {

    /**
     * Loads from a stream of PEM files and stores under alias 'server'
     *
     * @param stream input stream with multiple PEMs (including certificate chain and key)
     * @param password not used, password protection is not supported
     * @throws IOException on input error
     * @throws NoSuchAlgorithmException - not thrown
     * @throws CertificateException if loading is failed
     */
    @Override
    public void engineLoad(InputStream stream, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException {
        store.put("server", new PemCertKey(stream));
    }
}
