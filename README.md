# simple-pem-keystore

A java keystore implementation to use PEM files directly, instead of converting them to PKCS#12 or the clumsy jks format. This makes interoperability with standard webservers easier as they can use the same key/certificate files.

The keystore also implements scheduled/automatic reloading of certificates in case of change, so it can be used with short lived certificates, for example Let's Encrypt certificates, without application reset (or creating a new SSLContext / Socket).
 
## Compile

```Shell
./gradlew jar
```

## Get

The latest release version (0.3) is available in the Maven Central repository.

For maven:

```xml
	<dependency>
	    <groupId>io.r2</groupId>
	    <artifactId>simple-pem-keystore</artifactId>
	    <version>0.3</version>
	</dependency>
```

For gradle:

```gradle
	compile group: 'io.r2', name: 'simple-pem-keystore', version: '0.3'
```

## Registering the security provider

Before using the new key store, the security provider has to be registered in Java.

```java
    // directly
    Security.addProvider(new io.r2.simplepemkeystore.SimplePemKeyStoreProvider());
    
    // or using a shorthand syntax
    io.r2.simplepemkeystore.SimplePemKeyStoreProvider.register();
```

As the component is a fully compliant JCE provider, it may also be registered globally in the JRE. Please refer to JCE documentation on how to do this.

Note: If the application is running under Security manager which is not allowing adding new providers, you can't use this component.

## Usage - simple PEM keystore

The simple PEM keystore reads concatenated PEMs, which contains the key and the full certificate chain. The certificate for the domain must be in the first position in the chain.

```java
    KeyStore ks = KeyStore.getInstance("simplepem");
    ks.load( new FileInputStream("full.pem"), new char[0] );
```

A convenience helper class is included, the MultiFileConcatSource concatenates multiple pem files into a single input source

```java
    KeyStore ks = KeyStore.getInstance("simplepem");
    ks.load(
            MultiFileConcatSource.fromFiles(
                    "cert.pem",
                    "chain.pem",
                    "key.pem"
            ).build(),
            new char[0] // no password
    );
```

Please note that this key store does not support password, the password parameter is required for API compatibility but not used.

The certificate is loaded with alias 'server'.

## Multiple certificates with simplepem

*new in 0.2*

The simplepem provider now supports loading multiple certificates from a single concatenated source. To use this feature, add a metadata block between the certificates:

```
alias: client
creationdate: ISO-8601 time
```

The creationdate is optional, it defaults to the current time at the time of loading, if not present. Metadata should be outside the ----BEGIN/END blocks.

The MultiFileConcatSource helper also supports adding these metadata fields, for convenience, for example

```java
    KeyStore ks = KeyStore.getInstance("simplepem");
    ks.load(
            new MultiFileConcatSource()
                .alias("server")
                    .add("cert.pem")
                    .add("key.pem")
                .alias("client")
                .creationDate(Instant.now())
                    .add("client-cert.pem")
                    .add("client-key.pem")
                .build(),
            new char[0] // no password
    );
```

## Usage - reloading keystore

The reloading keystore takes a configuration JSON as input, which may define multiple certificates, which will be loaded into the store, and if the file dates change, they will be reloaded. Certificates must have an alias and a list of PEM files (which will be concatenated automatically). It takes the following input format:

```JSON
    {
      "refreshInterval": 3600,
      "certificates": {
        "letsencrypt": [
          "/etc/letsencrypt/live/mydomain.com/fullchain.pem",
          "/etc/letsencrypt/live/mydomain.com/privkey.pem"
        ]
      }
    }
```

The ReloadablePemKeyStoreConfig class is a convenient builder for input streams with such format:

```java
    // shorthand version for single Let's encrypt certificate
    InputStream in = ReloadablePemKeyStoreConfig.forLetsEncrypt("mydomain.com").asInputStream()
    
    // builder
    InputStream in = new ReloadablePemKeyStoreConfig()
            .addCertificate("server", new String[]{"server.pem"})
            .addCertificate("client", new String[]{"client.pem", "key.pem"})
            .withRefreshInterval(5)
            .asInputStream();    
```

These input streams can be used to load using the simplepemreload key store.

``` java
    KeyStore ks = KeyStore.getInstance("simplepemreload");
    ks.load( ReloadablePemKeyStoreConfig.forLetsEncrypt("mydomain.com").withRefreshInterval(60).asInputStream() );
```

Please note that the default key manager in Java will use caching, so if you use this key store with the default key manager, nothing will happen.

## Usage - reloading key manager

To fully utilize the reloading capability, the new key manager has to be used. This key manager can be used with other key stores as well, but will probably not do any good to them, as the default key stores are static. The key manager checks if the creation date for certificates in the key store has been changed, and if so, it will update its internal cache. 

```java
    // intiialize with keystore and password
    // this will use the default refresh interval of 1 hour
    KeyManagerFactory kmf = KeyManagerFactory.getInstance("simplepemreload");
    kmf.init(ks, password)
    
    // initialize with ExpiringCacheKeyManagerParameters
    KeyManagerFactory kmf = KeyManagerFactory.getInstance("simplepemreload");
    kmf.init( ExpiringCacheKeyManagerParameters.forKeyStore(ks).withRevalidation(60) );
```

*new in 0.2*

Now the "simplepem" provider also supports certificate reloading, when used with the "simplepemreload" key manager factory. To use this, simply load a new certificate (or set of certificates) with `ks.load`.

Note: when loading new certificates, the existing ones with same alias are overwritten, but it does not delete the ones with no reference in the new input. This is to be consistent with JCE, which expects certificates to not disappear after being used (KeyManager caches certificates).

## Usage - SSLContext setup example

```java
    KeyStore ks = KeyStore.getInstance("simplepemreload");
    ks.load( ReloadablePemKeyStoreConfig.forLetsEncrypt("mydomain.com").withRefreshInterval(60).asInputStream(), new char[0]);

    KeyManagerFactory kmf = KeyManagerFactory.getInstance("simplepemreload");
    kmf.init( ExpiringCacheKeyManagerParameters.forKeyStore(ks).withRevalidation(60) );

    KeyManager[] km = kmf.getKeyManagers();
    
    SSLContext ctx = SSLContext.getInstance("TLSv1.2");
    ctx.init(km, null /* use default trust manager */, null /* use default secure random */);       
```

## Javadoc

The javadoc for the public helper classes is available at https://r2.io/javadoc/simple-pem-keystore/

## License

Licensed under the MIT license. 
 
## Requirements

Java 8 is required to compile or run.
Also depends on jackson-databind.

