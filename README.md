# pem-server-keystore

A java keystore implementation to use PEM files directly, instead of converting them to PKCS#12 or the clumsy jks format. This makes interoperability with standard webservers easier as they can use the same key/certificate files.

The keystore also implements scheduled/automatic reloading of certificates in case of change, so it can be used with short lived certificates, for example Let's Encrypt certificates, without application reset (or creating a new SSLContext / Socket).
 
## Compile

```
 gradle test jar
 ```

## Get

*TODO*

## Registering the security provider

Before using the new key store, the security provider has to be registered in Java.

```java
// directly
Security.addProvider(new io.r2.simplempemkeystore.SimplePemKeyStoreProvider());

// or using a shorthand syntax
io.r2.simplempemkeystore.SimplePemKeyStoreProvider.register();
```

As the component is a fully compliant JCE provider, it may also be registered globally in the JRE. Please refer to JCE documentation on how to do this.

Note: If the application is running under Security manager which is not allowing adding new providers, you can't use this component.

## Usage

*TODO*


## License

Licensed under the MIT license. 
 
## Requirements

Java 8 is required to compile or run.
Also depends on jackson-databind 

