package no.nav.common.security.ldap

import org.slf4j.LoggerFactory

/**
 * A singleton object for getting username and password from KafkaServer JAAS context
 * This object is only valid on kafka broker running PLAIN SASL
 */

object JAASContext {

    private val log = LoggerFactory.getLogger(JAASContext::class.java)

    // extracting JAAS context from kafka server - prerequisite is  PLAINSASL context
    val username: String
    val password: String

    init {

        log.info("Read JAAS Context for authorization support")

        val options: Map<String, String> = try {
            val jaasFile = javax.security.auth.login.Configuration.getConfiguration()
            jaasFile.getAppConfigurationEntry("KafkaServer")
                    ?.get(0)
                    ?.options
                    ?.map { kv -> Pair<String, String>(kv.key, kv.value.toString()) }?.toMap() ?: emptyMap()
        } catch (e: SecurityException) {
            log.error("JAAS Context read exception - ${e.message}")
            emptyMap()
        }

        username = options["username"].toString()
        password = options["password"].toString()
    }
}