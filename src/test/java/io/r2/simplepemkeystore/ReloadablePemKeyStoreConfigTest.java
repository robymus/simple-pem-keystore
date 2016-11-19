package io.r2.simplepemkeystore;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.testng.annotations.Test;

import java.io.InputStream;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.*;

/**
 * Test json config creation
 */
public class ReloadablePemKeyStoreConfigTest {


    @Test
    public void testLetsEncrypt() throws Exception {
        String json = ReloadablePemKeyStoreConfig.forLetsEncrypt("mydomain.com").asJSON();
        assertThat(json).isEqualTo(
                "{\"refreshInterval\":3600,\"certificates\":{\"letsencrypt\":[\"/etc/letsencrypt/live/mydomain.com/fullchain.pem\",\"/etc/letsencrypt/live/mydomain.com/privkey.pem\"]}}"
        );
    }

    @Test
    public void testBuild() throws Exception {
        ReloadablePemKeyStoreConfig config = new ReloadablePemKeyStoreConfig()
                .addCertificate("server", new String[]{"server.pem"})
                .addCertificate("client", new String[]{"client.pem", "key.pem"})
                .withRefreshInterval(5);
        assertThat(config.getRefreshInterval()).isEqualTo(5);
        assertThat(config.getCertificates()).hasSize(2);
        assertThat(config.getCertificates().get("server")).containsExactly("server.pem");
        assertThat(config.getCertificates().get("client")).containsExactly("client.pem", "key.pem");
    }

    @Test
    public void testInputStream() throws Exception {
        byte[] buf = new byte[1024];
        try (InputStream in = ReloadablePemKeyStoreConfig.forLetsEncrypt("mydomain.com").asInputStream()) {
            int len = in.read(buf);
            buf = Arrays.copyOfRange(buf, 0, len);
        }
        assertThat(new String(buf)).isEqualTo(
                "{\"refreshInterval\":3600,\"certificates\":{\"letsencrypt\":[\"/etc/letsencrypt/live/mydomain.com/fullchain.pem\",\"/etc/letsencrypt/live/mydomain.com/privkey.pem\"]}}"
        );
    }

    @Test
    public void testParse() throws Exception {
        String json = "{\"refreshInterval\":5,\"certificates\":{\"server\":[\"server.pem\"],\"client\":[\"client.pem\",\"key.pem\"]}}";
        ObjectMapper mapper = new ObjectMapper();
        ReloadablePemKeyStoreConfig config = mapper.readValue(json, ReloadablePemKeyStoreConfig.class);
        assertThat(config.getRefreshInterval()).isEqualTo(5);
        assertThat(config.getCertificates()).hasSize(2);
        assertThat(config.getCertificates().get("server")).containsExactly("server.pem");
        assertThat(config.getCertificates().get("client")).containsExactly("client.pem", "key.pem");
    }


}