package io.r2.simplepemkeystore;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;

/**
 * Configuration for the reloadable
 */
public class ReloadablePemKeyStoreConfig {

    /** default refresh interval, in seconds - 1 hour */
    public static final long DEFAULT_REFRESH_INTERVAL = 3600;

    private final static ObjectMapper mapper = new ObjectMapper();

    /**
     * The refresh interval in seconds
     * Set to 0 to disable
     * (Values below 5 are all considered as disabled)
     */
    private long refreshInterval = DEFAULT_REFRESH_INTERVAL;

    /**
     * The certificates to load.
     * Each key in the map is an alias that will be used in the key store
     * The values are paths to pem files.
     * It can be a single pem file, or several (for example, cert, chain, key separated)
     *
     * In case of multiple files, the order is important!
     * Always put certificate before the certification chain
     * (if using a single file, keep this order as well)
     */
    private HashMap<String, String[]> certificates = new HashMap<>();

    @JsonProperty("refreshInterval")
    public long getRefreshInterval() {
        return refreshInterval;
    }

    @JsonProperty("certificates")
    public HashMap<String, String[]> getCertificates() {
        return certificates;
    }

    public void setRefreshInterval(long refreshInterval) {
        this.refreshInterval = refreshInterval;
    }

    public void setCertificates(HashMap<String, String[]> certificates) {
        this.certificates = certificates;
    }

    /**
     * Fluid builder interface - adds a certificate with a given alias and list of pem files
     *
     * @param alias alias to use
     * @param pemFiles the list of pem files to use
     * @return self, for chaining
     */
    public ReloadablePemKeyStoreConfig addCertificate(String alias, String[] pemFiles) {
        certificates.put(alias, pemFiles);
        return this;
    }

    /**
     * Adds a Let's encrypt certificate
     *
     * It assumes certificates are located at
     * /etc/letsencrypt/live/{domain}/{fullchain|privkey}.pem
     * @param alias the alias in the keystore
     * @param domain  the domain to create certificates for
     * @return self, for chaining
     */
    public ReloadablePemKeyStoreConfig addLetsEncrypt(String alias, String domain) {
        return addCertificate(alias, new String[] {
                "/etc/letsencrypt/live/" + domain + "/fullchain.pem",
                "/etc/letsencrypt/live/" + domain + "/privkey.pem"
        });

    }

    /**
     * Fluid buidler interface - sets refresh interval
     *
     * @param interval new refresh interval (in seconds)
     * @return self, for chaining
     */
    public ReloadablePemKeyStoreConfig withRefreshInterval(long interval) {
        refreshInterval = interval;
        return this;
    }

    /**
     * Converts object to JSON string
     *
     * @return object as JSON string
     */
    public String asJSON() {
        try {
            return mapper.writeValueAsString(this);
        }
        catch (JsonProcessingException e) {
            // should not happen when writing
            return "/invalid/";
        }
    }

    /**
     * Converts object to JSON string
     *
     * @return object as JSON string
     */
    public InputStream asInputStream() {
        try {
            return new ByteArrayInputStream(mapper.writeValueAsBytes(this));
        }
        catch (JsonProcessingException e) {
            // should not happen when writing
            return new ByteArrayInputStream("/invalid/".getBytes());
        }
    }


    /**
     * Shorthand method to create a config for a Let's encrypt certificate
     *
     * @param domain  the domain to create certificates for
     * @return self, for chaining
     * @see ReloadablePemKeyStoreConfig#addLetsEncrypt(String, String)
     */
    public static ReloadablePemKeyStoreConfig forLetsEncrypt(String domain) {
        return new ReloadablePemKeyStoreConfig().addLetsEncrypt("letsencrypt", domain);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        ReloadablePemKeyStoreConfig that = (ReloadablePemKeyStoreConfig) o;

        if (getRefreshInterval() != that.getRefreshInterval()) return false;
        return getCertificates().equals(that.getCertificates());

    }

    @Override
    public int hashCode() {
        int result = (int) (getRefreshInterval() ^ (getRefreshInterval() >>> 32));
        result = 31 * result + getCertificates().hashCode();
        return result;
    }

    @Override
    public String toString() {
        return asJSON();
    }
}
