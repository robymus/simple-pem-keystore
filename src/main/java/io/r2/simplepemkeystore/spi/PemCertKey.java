package io.r2.simplepemkeystore.spi;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.*;
import java.util.stream.Collectors;

/**
 * A certificate chain and private key read from PEM
 * Note: intentionally defined as package access only
 */
class PemCertKey {

    public static String META_KEY_ALIAS = "alias";
    public static String META_KEY_CREATIONDATE = "creationdate";

    protected String alias;
    protected Date creationDate;
    protected Map<String, String> metaData;
    protected Key privateKey;
    protected List<Certificate> certificateChain;
    protected Certificate[] certificateChainPacked;

    /**
     * Create an empty object, for adding fields later
     */
    public PemCertKey() {
        alias = "server"; // default alias
        creationDate = new Date();
        privateKey = null;
        certificateChain = new ArrayList<>();
        metaData = new HashMap<>();
    }

    /**
     * Finish construction of this object
     * @return object for chaining
     */
    public PemCertKey build() {
        // put to packed structure
        certificateChainPacked = certificateChain.toArray(new Certificate[0]);
        return this;
    }

    /**
     * Sets metadata and parses alias/creationDate, if available
     *
     * @param metaData input unparsed metadata
     * @throws CertificateException if creationDate exists but invalid format
     */
    public void setMetaData(Map<String, String> metaData) throws CertificateException {
        this.metaData = metaData;
        if (metaData.containsKey(META_KEY_ALIAS)) {
            alias = metaData.get(META_KEY_ALIAS);
        }
        if (metaData.containsKey(META_KEY_CREATIONDATE)) {
            Instant t;
            try {
                t = Instant.parse(metaData.get(META_KEY_CREATIONDATE));
            }
            catch (DateTimeParseException e) {
                throw new CertificateException(e);
            }
            creationDate = Date.from(t);
        }
    }

    /**
     * Internal method used during parsing : sets the private key in this entry
     *
     * @param key the chunk containing certificate
     * @param chunkType pkcs8_key or rsa_key - other values throw NoSuchAlgorithmException
     * @throws CertificateException if key already exists
     */
    public void setPrivateKey(List<String> key, PemStreamParser.ChunkType chunkType) throws CertificateException, NoSuchAlgorithmException {
        if (privateKey != null) throw new CertificateException("More than one private key in PEM input");

        String b64key = String.join("", key.subList(1, key.size() - 1));
        byte[] binKey = Base64.getDecoder().decode(b64key);

        KeySpec keySpec;

        switch (chunkType) {
            case pkcs8_key:
                keySpec = new PKCS8EncodedKeySpec(binKey);
                break;
            case pkcs1_key:
                keySpec = new PKCS8EncodedKeySpec(PKCS1Converter.toPKCS8(binKey));
                break;
            default:
                // this should not happen, as it is called only for matching types
                throw new NoSuchAlgorithmException("Invalid private key type: "+chunkType);
        }

        KeyFactory kf = KeyFactory.getInstance("RSA");
        try {
            privateKey = kf.generatePrivate(keySpec);
        }
        catch (InvalidKeySpecException e) {
            throw new NoSuchAlgorithmException(e);
        }
    }

    /**
     * Add a new certificate to the chain
     * @param chunk the chunk containing certificate
     */
    public void addCertificate(List<String> chunk) throws CertificateException {
        InputStream is = new ByteArrayInputStream(
                String.join("\n", chunk).getBytes(StandardCharsets.UTF_8)
        );
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        certificateChain.add(cf.generateCertificate(is));
    }

    /**
     * Gets the alias of this certificate
     * @return alias of certificate
     */
    public String getAlias() {
        return alias;
    }

    /**
     * Change alias of certificate
     * @param alias new alias
     */
    public void setAlias(String alias) {
        this.alias = alias;
        metaData.put(META_KEY_ALIAS, alias);
    }

    /**
     * Creation date is unknown in this store, so return object creation date
     * @return creation date
     */
    public Date getCreationDate() {
        return creationDate;
    }

    /**
     * Change creation date of certificate
     * @param creationDate new alias
     */
    public void setCreationDate(Date creationDate) {
        this.creationDate = creationDate;
        metaData.put(META_KEY_CREATIONDATE, creationDate.toInstant().toString());
    }

    /**
     * Returns the optional metadata fields in this certificate (including alias and creationDate)
     * @return map of metadata keys and values
     */
    public Map<String, String> getMetaData() {
        return metaData;
    }

    /**
     * Gets the private key - private keys are not password protected
     *
     * @return the private key
     * @throws UnrecoverableKeyException if password is incorrect
     */
    public Key getPrivateKey() throws UnrecoverableKeyException {
        return privateKey;
    }

    /**
     * @return certificate chain
     */
    public Certificate[] getCertificateChain() {
        return certificateChainPacked;
    }

    /**
     * @return the certificate or null if not found in input
     */
    public Certificate getCertificate() {
        return certificateChainPacked.length > 0 ? certificateChainPacked[0] : null;
    }

    /**
     * @return true if input has a key
     */
    public boolean hasKey() {
        return privateKey != null;
    }

    /**
     * @return true if input has a certificate
     */
    public boolean hasCertificate() {
        return certificateChainPacked.length > 0;
    }

    /**
     * @return true if parameter certificate matches this one
     */
    public boolean matchesCertificate(Certificate other) {
        if (certificateChainPacked.length == 0) return false;
        return certificateChainPacked[0].equals(other);
    }

}
