# pem-server-keystore

A simple java keystore implementation to use pem files directly, instead of converting them to PKCS#12 or the clumsy jks format. This makes interoperability with standard webservers easier as they can use the same key/certificate files.

The keystore also implements scheduled/automatic reloading of certificates in case of change, so it can be used with short lived certificates, for example Let's Encrypt certificates, without application reset (or creating a new SSLContext / Socket).
 
## Compile

````
 gradle test jar
 ````

## Get

*TODO*

## Usage

*TODO*

## Usage - direct

*TODO*

Note: Security manager not allowing adding new provider 

## Installing into JRE

**Important:** as this requires global modification in your JRE it makes applications less portable. 

## License

Licensed under the MIT license. 
 
## Status

- Basic functionality finished
- Unit tests pass
- TODO: Documentation (this file)
- TODO: live test
- TODO: publishing