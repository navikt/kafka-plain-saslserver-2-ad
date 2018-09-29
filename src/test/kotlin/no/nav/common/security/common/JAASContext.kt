package no.nav.common.security.common

import javax.security.auth.login.AppConfigurationEntry
import javax.security.auth.login.Configuration

/**
 *  An object for setting minimum JAAS context as on Kafka server in PLAIN SASL scenario
 *  - username and password for kafka broker
 *
 *  This is used for getting bindDN  in LDAP authorization context
 *  A prerequisite is of course username/pwd as part of in-memory LDAP
 *
 *  The setUp function must be invoked before test cases
 */

object JAASContext {

    fun setUp() {

        val config = object : Configuration() {
            override fun getAppConfigurationEntry(name: String): Array<AppConfigurationEntry> {
                return arrayOf(
                        AppConfigurationEntry(
                                "org.apache.kafka.common.security.plain.PlainLoginModule required",
                                AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
                                hashMapOf<String, Any>("username" to "igroup", "password" to "itest")
                        )
                )
            }

            override fun refresh() {
                // ignored
            }
        }
        // make the JAAS config available
        Configuration.setConfiguration(config)
    }
}