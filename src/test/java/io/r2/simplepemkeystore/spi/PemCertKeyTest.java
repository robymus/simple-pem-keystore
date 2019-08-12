package io.r2.simplepemkeystore.spi;

import io.r2.simplepemkeystore.MultiFileConcatSource;
import org.testng.annotations.Test;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.time.temporal.TemporalUnit;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.*;

/**
 * Tests PemCertKey
 */
public class PemCertKeyTest {


    @Test
    public void testCertOnly() throws Exception {
        InputStream in = new FileInputStream("src/test/resources/cert.pem");
        PemCertKey t = PemStreamParser.parseCertificate(in);

        Certificate cert = t.getCertificate();
        assertThat(cert).isNotNull();
        assertThat(cert.getType()).isEqualTo("X.509");

        assertThat(t.hasCertificate()).isTrue();
        assertThat(t.getCertificateChain()).hasSize(1);
        assertThat(t.getCertificateChain()[0]).isEqualTo(cert);

        assertThat(t.matchesCertificate(cert)).isTrue();
        assertThat(t.matchesCertificate(null)).isFalse();

        assertThat(t.hasKey()).isFalse();
        assertThat(t.getPrivateKey()).isNull();

        assertThat(t.getCreationDate()).isCloseTo(new Date(), 5000);
    }

    @Test
    public void testKeyOnly() throws Exception {
        InputStream in = new FileInputStream("src/test/resources/key.pem");
        PemCertKey t = PemStreamParser.parseCertificate(in);

        assertThat(t.hasCertificate()).isFalse();
        assertThat(t.getCertificateChain()).hasSize(0);
        assertThat(t.getCertificate()).isNull();

        assertThat(t.matchesCertificate(null)).isFalse();

        assertThat(t.hasKey()).isTrue();
        assertThat(t.getPrivateKey().getFormat()).isEqualTo("PKCS#8");
        assertThat(t.getPrivateKey().getAlgorithm()).isEqualTo("RSA");

        assertThat(t.getCreationDate()).isCloseTo(new Date(), 5000);
    }


    @Test
    public void testCertKey() throws Exception {
        InputStream in = MultiFileConcatSource.fromFiles(
                "src/test/resources/certchain.pem",
                "src/test/resources/key.pem"
        ).build();
        PemCertKey t = PemStreamParser.parseCertificate(in);

        Certificate cert = t.getCertificate();
        assertThat(cert).isNotNull();
        assertThat(cert.getType()).isEqualTo("X.509");

        assertThat(t.hasCertificate()).isTrue();
        assertThat(t.getCertificateChain()).hasSize(2);
        assertThat(t.getCertificateChain()[0]).isEqualTo(cert);

        assertThat(t.matchesCertificate(cert)).isTrue();
        assertThat(t.matchesCertificate(t.getCertificateChain()[1])).isFalse();
        assertThat(t.matchesCertificate(null)).isFalse();

        assertThat(t.hasKey()).isTrue();
        assertThat(t.getPrivateKey().getFormat()).isEqualTo("PKCS#8");
        assertThat(t.getPrivateKey().getAlgorithm()).isEqualTo("RSA");

        assertThat(t.getCreationDate()).isCloseTo(new Date(), 5000);
    }

    @Test
    public void testMetaData() throws Exception {
        Instant t = Instant.now().minus(1, ChronoUnit.HOURS);
        InputStream in = new MultiFileConcatSource()
                .alias("myAlias")
                .creationDate(t)
                .add("src/test/resources/certchain.pem")
                .add("src/test/resources/key.pem")
                .build();

        PemCertKey certKey = PemStreamParser.parseCertificate(in);

        assertThat(certKey.getAlias()).isEqualTo("myAlias");
        assertThat(certKey.getCreationDate()).isEqualTo(Date.from(t));
    }

    @Test
    public void testMultiCert() throws Exception {
        InputStream in = new MultiFileConcatSource()
                .alias("anna")
                .add("src/test/resources/certchain.pem")
                .add("src/test/resources/key.pem")
                .alias("r2")
                .add("src/test/resources/selfcert.pem")
                .add("src/test/resources/selfkey.pem")
                .build();

        List<PemCertKey> list = PemStreamParser.parseCertificateList(in);

        assertThat(list).hasSize(2);
        PemCertKey anna = list.get(0);
        assertThat(anna.getAlias()).isEqualTo("anna");
        Certificate[] cert_anna = anna.getCertificateChain();
        assertThat(cert_anna[0]).isInstanceOf(X509Certificate.class);
        assertThat(((X509Certificate)cert_anna[0]).getSubjectX500Principal().getName()).isEqualTo("CN=anna.apn2.com");
        PemCertKey r2 = list.get(1);
        assertThat(r2.getAlias()).isEqualTo("r2");
        Certificate[] cert_r2 = r2.getCertificateChain();
        assertThat(cert_r2[0]).isInstanceOf(X509Certificate.class);
        assertThat(((X509Certificate)cert_r2[0]).getSubjectX500Principal().getName()).isEqualTo("CN=self.signed.cert,O=Radical Research,ST=NA,C=IO");
    }

}