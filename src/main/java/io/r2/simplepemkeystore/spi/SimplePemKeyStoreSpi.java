package io.r2.simplepemkeystore.spi;

import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * A simple (non-reloadable) PEM based key store
 */
public class SimplePemKeyStoreSpi extends BasePemKeyStore {

    /**
     * Loads from a stream of PEM files
     * If no alias metadata present, it stores under alias 'server'
     * Otherwise can parse multiple certificates separated by alias metadata
     *
     * @param stream input stream with multiple PEMs (including certificate chain and key)
     * @param password not used, password protection is not supported
     * @throws IOException on input error
     * @throws NoSuchAlgorithmException - not thrown
     * @throws CertificateException if loading is failed
     */
    @Override
    public void engineLoad(InputStream stream, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException {
        List<PemCertKey> certList = PemStreamParser.parseCertificateList(stream);
        // check for alias conflict in input
        Map<String, PemCertKey> newCerts = new HashMap<>();
        for (PemCertKey certkey : certList) {
            String alias = certkey.getAlias();
            if (newCerts.putIfAbsent(alias, certkey) != null) {
                throw new CertificateException("Multiple entries with the same alias: " + alias);
            }
        }
        // no alias conflict: store everything (update existing also)
        store.putAll(newCerts);
    }
}
