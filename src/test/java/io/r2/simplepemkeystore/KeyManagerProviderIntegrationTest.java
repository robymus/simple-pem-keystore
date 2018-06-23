package io.r2.simplepemkeystore;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import javax.net.ssl.*;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests if registering as a provider works and keymanager is operational
 */
public class KeyManagerProviderIntegrationTest extends HttpsBaseFunctions {

    @BeforeClass
    public void registerProvider() throws Exception {
        SimplePemKeyStoreProvider.register();
    }

    protected KeyStore getKeyStore() throws Exception {
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
    public void testHttps() throws Exception {
        KeyStore ks = getKeyStore();

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("simplepemreload");
        kmf.init( ExpiringCacheKeyManagerParameters.forKeyStore(ks).withRevalidation(5) );

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
