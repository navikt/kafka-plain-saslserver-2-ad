FROM openjdk:11-jdk
WORKDIR /kafka-plain-saslserver-2-ad
COPY . .
RUN ./gradlew build test
RUN ./gradlew shadowJar -x test

FROM confluentinc/cp-kafka:5.0.0
COPY --from=0 /kafka-plain-saslserver-2-ad/build/libs/kafka-plain-saslserver-2-ad-* /usr/share/java/kafka

ENV KAFKA_OPTS='-Djava.security.auth.login.config=/etc/kafka/kafka_server_jaas.conf'
ENV CLASSPATH="/etc/kafka"
