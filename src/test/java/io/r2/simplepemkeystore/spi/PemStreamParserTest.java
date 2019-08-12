package io.r2.simplepemkeystore.spi;

import org.testng.annotations.Test;

import java.io.FileInputStream;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.*;

/**
 * ok/fail tests for pem stream parser
 */
public class PemStreamParserTest {

    // TODO: metadata

    @Test
    public void testParseOk() throws Exception {
        FileInputStream in = new FileInputStream("src/test/resources/parser-ok.pem");
        ArrayList<PemStreamParser.ChunkType> chunks = new ArrayList<>();
        ArrayList<String> parsed = new ArrayList<>();
        PemStreamParser.parse(in, (type, chunk) -> {
            chunks.add(type);
            parsed.add(String.join("\n", chunk));
        });
        assertThat(chunks).containsExactly(
                PemStreamParser.ChunkType.certificate,
                PemStreamParser.ChunkType.certificate,
                PemStreamParser.ChunkType.key,
                PemStreamParser.ChunkType.end
        );
        assertThat(parsed).containsExactly(
                "-----BEGIN CERTIFICATE-----\n" +
                "cert1\n" +
                "data1\n" +
                "-----END CERTIFICATE-----",

                "-----BEGIN CERTIFICATE-----\n" +
                "cert2\n" +
                "data2\n" +
                "-----END CERTIFICATE-----",

                "-----BEGIN PRIVATE KEY-----\n" +
                "key1\n" +
                "datak1\n" +
                "-----END PRIVATE KEY-----",

                ""
        );
    }

    @Test(expectedExceptions = CertificateException.class)
    public void testParseFail() throws Exception {
        FileInputStream in = new FileInputStream("src/test/resources/parser-fail.pem");
        PemStreamParser.parse(in, (type, chunk) -> {});
    }


}