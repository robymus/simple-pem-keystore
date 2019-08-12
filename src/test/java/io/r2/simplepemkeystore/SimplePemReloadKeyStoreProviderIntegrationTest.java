package io.r2.simplepemkeystore;

import com.sun.net.httpserver.HttpsServer;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.security.Key;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests if registering as a provider works and simplepemreload keystore is operational
 */
public class SimplePemReloadKeyStoreProviderIntegrationTest extends HttpsBaseFunctions {

    @BeforeClass
    public void registerProvider() throws Exception {
        Security.addProvider(new SimplePemKeyStoreProvider());
    }

    private KeyStore getKeyStore() throws Exception {
        KeyStore ks = KeyStore.getInstance("simplepemreload");
        ks.load(
                new ReloadablePemKeyStoreConfig()
                .addCertificate("server", new String[] {
                        "src/test/resources/certchain.pem",
                        "src/test/resources/key.pem"
                })
                .asInputStream(),
                new char[0] // no password
        );
        return ks;
    }

    @Test
    public void testGetKeyStore() throws Exception {
        KeyStore ks = getKeyStore();

        Certificate[] cert = ks.getCertificateChain("server");
        Key key = ks.getKey("server", new char[0]);

        assertThat(cert).hasSize(2);
        assertThat(cert[0].getType()).isEqualTo("X.509");
        assertThat(key.getFormat()).isEqualTo("PKCS#8");
        assertThat(key.getAlgorithm()).isEqualTo("RSA");
    }

    @Test
    public void testSetupSSLContext() throws Exception {
        KeyStore ks = getKeyStore();

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, new char[0]);

        KeyManager[] km = kmf.getKeyManagers();
        assertThat(km).hasSize(1);

        SSLContext ctx = SSLContext.getInstance("TLSv1.2");
        ctx.init(km, null, null);
    }


    @Test
    public void testHttps() throws Exception {

        KeyStore ks = getKeyStore();

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, new char[0]);

        KeyManager[] km = kmf.getKeyManagers();
        assertThat(km).hasSize(1);

        SSLContext ctx = SSLContext.getInstance("TLSv1.2");
        ctx.init(km, null, null);

        HttpsServer server = startHttpsServer(ctx);

        try {
            HttpsURLConnection conn = createClientConnection();

            assertThat(conn.getPeerPrincipal().getName()).isEqualTo("CN=anna.apn2.com");
        }
        finally {
            // stop server
            server.stop(0);
        }
    }

    @Test
    public void testMultiAlias() throws Exception {
        KeyStore ks = KeyStore.getInstance("simplepemreload");
        ks.load(
                new ReloadablePemKeyStoreConfig()
                        .addCertificate("anna", new String[] {
                                "src/test/resources/certchain.pem",
                                "src/test/resources/key.pem"
                        })
                        .addCertificate("r2", new String[] {
                                "src/test/resources/selfcert.pem",
                                "src/test/resources/selfkey.pem"
                        })
                        .asInputStream(),
                new char[0] // no password
        );

        Certificate[] cert_anna = ks.getCertificateChain("anna");
        assertThat(cert_anna[0]).isInstanceOf(X509Certificate.class);
        assertThat(((X509Certificate)cert_anna[0]).getSubjectX500Principal().getName()).isEqualTo("CN=anna.apn2.com");
        Certificate[] cert_r2 = ks.getCertificateChain("r2");
        assertThat(cert_r2[0]).isInstanceOf(X509Certificate.class);
        assertThat(((X509Certificate)cert_r2[0]).getSubjectX500Principal().getName()).isEqualTo("CN=self.signed.cert,O=Radical Research,ST=NA,C=IO");
    }

}
