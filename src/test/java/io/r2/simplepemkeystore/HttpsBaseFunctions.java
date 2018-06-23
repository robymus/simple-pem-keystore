package io.r2.simplepemkeystore;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.OutputStream;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Common base functions for HTTPS testing
 */
public class HttpsBaseFunctions {

    public static final int PORT_MIN = 59000;
    public static final int PORT_MAX = 60000;
    public int port;

    protected HttpsServer startHttpsServer(SSLContext ctx) throws Exception {
        for (int i = PORT_MIN; i < PORT_MAX; i++) {
            port = i;
            try {
                InetSocketAddress localhost = new InetSocketAddress(InetAddress.getLoopbackAddress(), port);
                HttpsServer server = HttpsServer.create(localhost,  0);
                server.setHttpsConfigurator(new HttpsConfigurator(ctx));

                server.createContext("/", (t) -> {
                    byte[] data = "success".getBytes();
                    t.sendResponseHeaders(HttpURLConnection.HTTP_OK, data.length);
                    OutputStream o = t.getResponseBody();
                    o.write(data);
                    o.close();
                });
                server.setExecutor(null);
                server.start();

                return server;
            }
            catch (BindException be) {
                // ignore, try next port
            }
        }
        throw new Exception("Can't find available ports for integration testing");
    }

    protected HttpsURLConnection createClientConnection() throws Exception {
        // disable client cert verification
        TrustManager trustallcerts = new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
            }

            @Override
            public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return null;
            }
        };
        SSLContext clientContext = SSLContext.getInstance("SSL");
        clientContext.init(null, new TrustManager[]{trustallcerts}, new SecureRandom());

        // try to connect to server

        String _url = "https://"+InetAddress.getLoopbackAddress().getHostAddress()+":"+port;
        URL url = new URL(_url);
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
        conn.setSSLSocketFactory(clientContext.getSocketFactory());
        conn.setHostnameVerifier((hostname, session) -> true);

        assertThat(conn.getResponseCode()).isEqualTo(HttpsURLConnection.HTTP_OK);

        byte[] buffer = new byte[1024];
        int len = 0;
        int read;
        while ( (read = conn.getInputStream().read(buffer, len, buffer.length-len)) > 0) {
            len += read;
        };
        buffer = Arrays.copyOfRange(buffer, 0, len);

        assertThat(buffer).containsExactly("success".getBytes(StandardCharsets.UTF_8));

        return conn;
    }
}
