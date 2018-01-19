# KafkaPlainSaslServer2AD
Enhancing kafka PlainSaslServer with LDAP binding

./gradlew clean build
./gradlew shadowJar

The latter will create the <name><version>-all.jar to be placed into <java home>/jre/ext 
In addition add the following to java.security
security.provider.11=org.navit.common.security.plain.PlainSaslServerProvider

NB! See TODOs and only working agains local ldap on 10389...
