package no.nav.common.security.ldap

import org.slf4j.LoggerFactory

object JAASContext {

    private val log = LoggerFactory.getLogger(JAASContext::class.java)

    // extracting JAAS context from kafka server - prerequisite is  PLAINSASL context
    val username: String
    val password: String

    init {

        log.info("Read JAAS Context for authorization support")

        val options: Map<String,String> = try {
            val jaasFile = javax.security.auth.login.Configuration.getConfiguration()
            val entries = jaasFile.getAppConfigurationEntry("KafkaServer")
            entries
                    ?.get(0)
                    ?.options
                    ?.let { it.map { Pair<String,String>(it.key, it.value.toString()) }.toMap() } ?: emptyMap()
        }
        catch (e: SecurityException) {
            log.error("JAAS Context read exception - ${e.message}")
            emptyMap()
        }

        username = options["username"].toString()
        password = options["password"].toString()
    }
}