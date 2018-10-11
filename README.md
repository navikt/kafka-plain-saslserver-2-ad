# kafka-plain-saslserver-2-ad [![Build Status](https://travis-ci.org/navikt/kafka-plain-saslserver-2-ad.svg?branch=master)](https://travis-ci.org/navikt/kafka-plain-saslserver-2-ad)
Enhancing kafka 2.x with
- customized SimpleLDAPAuthentication using LDAPS simple bind for authentication
- customized SimpleACLAuthorizer using LDAPS compare-matched for group membership verification

Thus, moving authentication from user and passwords in JAAS context file on kafka brokers to LDAP server

By defining Read/Write allowance with LDAP groups, authorization is moved from 
Zookeeper Access Control Lists to group membership verification.

Binding and group membership information is cached (limited lifetime after write),
giving minor performance penalty and reduced LDAPS traffic.

## Tools
- Kotlin
- Gradle build tool
- Spek test framework

## Components

1. Unboundid LDAP SDK for LDAPS interaction
2. Caffeine Cache
3. YAML Configuration for LDAP baseDN for users, groups and more. See src/test/resources/ldapconfig.yaml for details

**Observe** that the directory hosting yaml configuration file must be in CLASSPATH.

## Kafka configuration examples

JAAS context file on Kafka broker use the standard class for plain login module during authentication

```
KafkaServer{
org.apache.kafka.common.security.plain.PlainLoginModule required
username="x"
password="y";
};
```

Example of Kafka server.properties for using the customized classes for authentication and authorization. The example
focus on minimum configuration only (sasl plaintext). A production environment utilize plain with TLS.

```
...
listeners=SASL_PLAINTEXT://localhost:9092
security.inter.broker.protocol=SASL_PLAINTEXT
sasl.mechanism.inter.broker.protocol=PLAIN
sasl.enabled.mechanisms=PLAIN 

listener.name.sasl_plaintext.plain.sasl.server.callback.handler.class=no.nav.common.security.authentication.SimpleLDAPAuthentication
authorizer.class.name=no.nav.common.security.authorization.SimpleLDAPAuthorizer
...
```

## Using the docker image
The docker image can't currently be used standalone, the Dockerfile is supposed to be extended by adding the config file
`/etc/kafka/ldapconfig.yaml` and the jaas configuration `/etc/kafka/kafka_server_jaas.conf`, examples of these 
config files can be found in [NAVs kafka docker compose project](https://github.com/navikt/navkafka-docker-compose)

## Testing

Use of Unboundid in-memory LDAP server for all test cases.

Tested on confluent.io version 5.x (related to apache kafka 2.x)

See [Confluent Open Source distribution](https://www.confluent.io/product/confluent-open-source/) in order to test locally.

The related [Wiki](https://github.com/navikt/KafkaPlainSaslServer2AD/wiki) has a detailed guide for local testing.

## Build 

```
./gradlew clean build
./gradlew shadowJar

The result is kafka-plain-salserver-2-ad-2.0_<version>.jar hosting authentication and authorization classes.
```
**Observe** that the directory hosting the given JAR file must be in CLASSPATH.

### Contact us
#### Code/project related questions can be sent to 
* Torstein Nesby, `torstein.nesby@nav.no`
* Trong Huu Nguyen, `trong.huu.nguyen@nav.no`

For internal resources, send requests/questions to slack#kafka
