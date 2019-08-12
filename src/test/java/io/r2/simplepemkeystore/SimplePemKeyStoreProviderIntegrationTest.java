package io.r2.simplepemkeystore;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import javax.net.ssl.*;
import java.io.IOException;
import java.io.OutputStream;
import java.io.File;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.*;

/**
 * Tests if registering as a provider works and simplepem keystore is operational
 */
public class SimplePemKeyStoreProviderIntegrationTest extends HttpsBaseFunctions {

    @BeforeClass
    public void registerProvider() throws Exception {
        Security.addProvider(new SimplePemKeyStoreProvider());
    }

    private KeyStore getKeyStore() throws Exception {
        KeyStore ks = KeyStore.getInstance("simplepem");
        ks.load(
                MultiFileConcatSource.fromFiles(
                        "src/test/resources/certchain.pem",
                        "src/test/resources/key.pem"
                ).build(),
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


}
