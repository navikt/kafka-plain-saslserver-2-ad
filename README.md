# KafkaPlainSaslServer2AD
Enhancing kafka PlainSaslServer with LDAP binding.

## Technologies
- Kotlin
- Gradle build tool
## Components

1. Use of Unbinded LDAP SDK for LDAPProxy class
2. The LDAPProxy is based on adconfig.yaml - see src/test/resources/adconfig.yaml for details
3. Kafka PlainSaslServer use LDAPProxy instead of listed users/pwds in classic JAAS config

**Observe** that adconfig.yaml must be somewhere in CLASSPATH

## Example of Kafka JAAS config file

*KafkaServer{
org.navit.common.security.plain.PlainLoginModule required
username="x"
password="y";
};*

## Testing

LDAPProxySpec use Unbinded's in-memory LDAP server for all test cases

## Build 

./gradlew clean build

./gradlew shadowJar

./gradlew publish

shadowJar will create *KafkaPlainSaslServer2AD<version>-all.jar*
publish will deploy the jar-file to repo.adeo.no
