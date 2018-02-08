# KafkaPlainSaslServer2AD
Enhancing kafka with
- customized PlainSaslServer using LDAPS simple bind for authentication
- customized SimpleACLAuthorizer using LDAPS compare-matched for group membership verification

Thus, avoiding user and passwords in JAAS context file on kafka brokers

By defining Read/Write allowance with Active Directory groups, authorization is moved from 
Zookeeper Access Control Lists to group membership.

Binding and group membership information is cached with google guava cache (limited lifetime after write),
giving minor performance penalty and reduced LDAPS traffic.

## Technologies
- Kotlin
- Gradle build tool

## Components

1. Unboundid LDAP SDK for LDAPS interaction
2. Google Guava Cache
3. YAML Configuration for LDAP baseDN for users and groups, see src/test/resources/adconfig.yaml for details

**Observe** that adconfig.yaml must be somewhere in CLASSPATH

## Kafka configuration examples

Example of JAAS context file on Kafka broker using the customized class for
authentication.

```
KafkaServer{
no.nav.common.security.plain.PlainLoginModule required
username="x"
password="y";
};
```

Example of Kafka server.properties for using the customized class for authorization.

```
authorizer.class.name=no.nav.common.security.authorization.SimpleLDAPAuthorizer
```


## Testing

Use of Unboundid in-memory LDAP server for all test cases.

Tested on confluent.io version 4.0.0.

## Build 

```
./gradlew clean build
./gradlew shadowJar
./gradlew publish
```

KafkaPlainSaslServer2AD-version-all.jar contains the relevant components only.

