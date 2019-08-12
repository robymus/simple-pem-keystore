package io.r2.simplepemkeystore.spi;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.*;

/**
 * Parses a stream of PEM encoded X.509 chunks
 */
public class PemStreamParser {

    protected InputStream in;

    public enum ChunkType { certificate, key, metaData, end }

    public PemStreamParser(InputStream in) {
        this.in = in;
    }

    /**
     * Parses input stream, looks for certificate and key chunks and sends them to the consumer
     *
     * @param consumer receives all chunks with type and the chunk content as list of lines
     *                 the list of lines include the chunk header and footer as well
     * @throws IOException on input errors
     * @throws CertificateException if parsing fails
     * @throws NoSuchAlgorithmException in case of cryptographic algorithm problems
     */
    public void parse(ChunkConsumer consumer) throws IOException, CertificateException, NoSuchAlgorithmException {
        List<String> chunk = new ArrayList<>();
        boolean inChunk = false;
        String chunkEndMarker = null;
        ChunkType currentChunkType = null;

        try (BufferedReader r = new BufferedReader(new InputStreamReader(in))) {
            String line;
            while ( (line = r.readLine()) != null) {
                line = line.trim(); // just to be sure
                if (line.length() == 0) continue; // ignore empty lines

                // inside chunk
                if (inChunk) {
                    // check for end of chunk
                    if (line.equals(chunkEndMarker)) {
                        chunk.add(line);
                        consumer.accept(currentChunkType, chunk);
                        chunk.clear();
                        inChunk = false;
                    }
                    else {
                        chunk.add(line);
                    }
                }
                // Not in chunk: start of chunk or metadata
                else {
                    switch (line) {
                        case "-----BEGIN CERTIFICATE-----":
                            if (chunk.size() > 0) {
                                // there was metadata before this
                                consumer.accept(ChunkType.metaData, chunk);
                                chunk.clear();
                            }
                            chunk.add(line);
                            currentChunkType = ChunkType.certificate;
                            inChunk = true;
                            chunkEndMarker = "-----END CERTIFICATE-----";
                            break;
                        case "-----BEGIN PRIVATE KEY-----":
                            if (chunk.size() > 0) {
                                // there was metadata before this
                                consumer.accept(ChunkType.metaData, chunk);
                                chunk.clear();
                            }
                            chunk.add(line);
                            currentChunkType = ChunkType.key;
                            inChunk = true;
                            chunkEndMarker = "-----END PRIVATE KEY-----";
                            break;
                        default:
                            // unknown chunk
                            if (line.startsWith("-----BEGIN ")) {
                                throw new CertificateException("Invalid chunk in input");
                            }
                            // everything else is metaData
                            chunk.add(line);
                    }
                }
            }
        }

        if (inChunk) {
            throw new CertificateException("Final chunk not closed");
        }
        if (chunk.size() > 0) {
            throw new CertificateException("Metadata at end of file");
        }

        consumer.accept(ChunkType.end, chunk);
    }

    /**
     * Shorthand notation for parsing input stream
     *
     * @param in the input to parse
     * @param consumer receives all chunks with type and the chunk content as list of lines
     *                 the list of lines include the chunk header and footer as well
     * @throws IOException on input errors
     * @throws CertificateException if parsing fails
     * @throws NoSuchAlgorithmException in case of cryptographic algorithm problems
     *
     * @see PemStreamParser#parse(ChunkConsumer)
     */
    public static void parse(InputStream in, ChunkConsumer consumer) throws IOException, CertificateException, NoSuchAlgorithmException {
        new PemStreamParser(in).parse(consumer);
    }

    /**
     * Consumer to be called for each chunk
     */
    @FunctionalInterface
    public interface ChunkConsumer {
        void accept(ChunkType chunkType, List<String> chunk) throws CertificateException, NoSuchAlgorithmException;
    }

    /**
     * Parse a metaData block
     *
     * @param metaData list of strings, format: "Key: Value"
     * @return metadata as a map: key to value, key is converted to lowercase
     * @throws CertificateException in case of incorrect format
     */
    public static Map<String, String> parseMetaData(List<String> metaData) throws CertificateException {
        Map<String, String> ret = new HashMap<>();
        for (String line : metaData) {
            String[] p = line.split(":", 2);
            if (p.length != 2) throw new CertificateException("Invalid line in metadata: "+line);
            ret.put(p[0].trim().toLowerCase(), p[1].trim());
        }
        return ret;
    }

    /**
     * Parse an input stream into a certificate list
     *
     * @param in the input to parse
     * @return list of parsed PemCertKey objects
     * @throws IOException on input errors
     * @throws CertificateException if parsing fails
     * @throws NoSuchAlgorithmException in case of cryptographic algorithm problems
     */
    public static List<PemCertKey> parseCertificateList(InputStream in) throws IOException, CertificateException, NoSuchAlgorithmException {
        List<PemCertKey> list = new ArrayList<>();

        PemStreamParser.parse(in, new ChunkConsumer() {
            // we are currently working on this one
            PemCertKey pending = null;

            @Override
            public void accept(ChunkType chunkType, List<String> chunk) throws CertificateException, NoSuchAlgorithmException {
                switch (chunkType) {
                    case metaData:
                        if (pending != null) {
                            list.add(pending.build());
                        }
                        pending = new PemCertKey();
                        pending.setMetaData(parseMetaData(chunk));
                        break;
                    case certificate:
                        // start a new, if this is the first block
                        if (pending == null) pending = new PemCertKey();
                        pending.addCertificate(chunk);
                        break;
                    case key:
                        // start a new, if this is the first block
                        if (pending == null) pending = new PemCertKey();
                        pending.setPrivateKey(chunk);
                        break;
                    case end:
                        if (pending != null) {
                            list.add(pending.build());
                        }
                        break;
                }
            }
        });

        return list;
    }

    /**
     * Parse an input stream into a single certificate
     *
     * @param in the input to parse
     * @return list of parsed PemCertKey objects
     * @throws IOException on input errors
     * @throws CertificateException if parsing fails
     * @throws NoSuchAlgorithmException in case of cryptographic algorithm problems
     */
    public static PemCertKey parseCertificate(InputStream in) throws IOException, CertificateException, NoSuchAlgorithmException {
        List<PemCertKey> list = parseCertificateList(in);
        if (list.size() != 1) {
            throw new CertificateException("Input must contain exactly one certificate");
        }
        return list.get(0);
    }


    /**
     * Parse an input stream into a single certificate, with creationData, alias override from arguments
     *
     * @param in the input to parse
     * @param alias the alias to set for the certificate
     * @param creationDate the date to set for the certificate
     * @return list of parsed PemCertKey objects
     * @throws IOException on input errors
     * @throws CertificateException if parsing fails
     * @throws NoSuchAlgorithmException in case of cryptographic algorithm problems
     */
    public static PemCertKey parseCertificate(InputStream in, String alias, Date creationDate) throws IOException, CertificateException, NoSuchAlgorithmException {
        PemCertKey ret = parseCertificate(in);
        ret.setAlias(alias);
        ret.setCreationDate(creationDate);
        return ret;
    }


}
