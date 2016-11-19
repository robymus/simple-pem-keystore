package io.r2.simplepemkeystore.spi;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.r2.simplepemkeystore.MultiFileConcatSource;
import io.r2.simplepemkeystore.ReloadablePemKeyStoreConfig;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Reloadable PEM based key store
 *
 * Normally a key store loads from an InputStream, so it has no access to the file system to be able to reload.
 * To work around this limitation, this class expects a specially formatted JSON document in the input stream,
 * which specifies the input file locations and refresh timeouts.
 *
 * This can be handcrafted, but even better if constructed using the ReloadablePemKeyStoreConfig helper class.
 *
 * Sample format:
 * {
 *     "refreshInterval": 3600,
 *     "certificates": {
 *          "server": [ "everything_in_one.pem" ],
 *          "server2": [ "cert.pem", "chain.pem", "key.pem" ]
 *     }
 * }
 */
public class ReloadablePemKeyStoreSpi extends BasePemKeyStore {

    /** current configuration */
    protected ReloadablePemKeyStoreConfig configuration;

    /** scheduler for the certificate refreshing task */
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);


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
        ObjectMapper mapper = new ObjectMapper();
        configuration = mapper.readValue(stream, ReloadablePemKeyStoreConfig.class);

        // load all certificates
        for (String alias : configuration.getCertificates().keySet()) {
            refreshCertificate(alias);
        };

        // schedule modification check and reload
        scheduler.scheduleAtFixedRate(()->{
            for (String alias : configuration.getCertificates().keySet()) {
                try {
                    refreshCertificate(alias);
                } catch (Exception e) {
                    // cache rebuild failed, keep the old one quietly
                }
            }
        }, configuration.getRefreshInterval(), configuration.getRefreshInterval(), TimeUnit.SECONDS);
    }

    /**
     * Refreshes a certificate if it has been changed
     * @param alias the alias of the certificate to reload
     * @throws IOException on input error
     * @throws CertificateException on certificate format error
     * @throws NoSuchAlgorithmException when required cryptographic algorithms are missing
     */
    protected void refreshCertificate(String alias) throws IOException, CertificateException, NoSuchAlgorithmException  {

        String[] files = configuration.getCertificates().get(alias);

        long fileTime = 0;
        for (String f : files) {
            Path path = new File(f).toPath();
            BasicFileAttributes attr = Files.readAttributes(path, BasicFileAttributes.class);
            fileTime = Math.max(fileTime, attr.lastModifiedTime().toMillis());

        }
        Date fileDate = new Date(fileTime);

        PemCertKey old = store.get(alias);
        if (old == null || old.getCreationDate().before(fileDate))
        {

            store.put(alias,
                    new PemCertKey(
                            MultiFileConcatSource.fromFiles(files).build(),
                            fileDate
                    )
            );

        }
    }
}
