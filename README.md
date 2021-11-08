# fusionauth-argon2id-native-password-encryptor

This plugin provides an implementation for generating argon2id password digests
in FusionAuth using Java Native Access (`jna`) which calls out to the natively
compiled reference C implementation of Argon2id. 

## Java Install
To install Java, you will need the OpenJDK. Due to licensing, you can't simply
use the Oracle JDK distribution due to 'commercial use'.

Hop over to [Adoptium](https://adoptium.net/?variant=openjdk11) to download the
OpenJDK for your platform.

## Building

This project uses Maven, so to build the required JAR file, you need to run:

```bash
$ mvn package
```

This will spit out a "shaded" uber JAR, that is a JAR file packaged with all 
required dependencies packed into a single JAR file.

## Deployment
### FusionAuth Cloud
The required JAR file need to be sent on to the FusionAuth's support team via 
email or via a support ticket, so they can plug it directly into the specific 
cloud deployment.

### FusionAuth
Take the shaded JAR and copy/paste/add it into FusionAuth's `plugin` folder.

## References
- [Argon2 Github repository](https://github.com/P-H-C/phc-winner-argon2)
- [Argon2 Binding for the JVM Github repository](https://github.com/phxql/argon2-jvm)
- [FusionAuth Plugins](https://fusionauth.io/docs/v1/tech/plugins/writing-a-plugin/)
