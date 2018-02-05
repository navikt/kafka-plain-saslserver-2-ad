package org.navit.common.security.authorization

import javax.security.auth.login.AppConfigurationEntry
import javax.security.auth.login.Configuration

/**
 *
 *  A class for setting JAAS context, required for testing authorization logic
 *
 */

object JAASContext {

    fun setUp() {

        class ReallyDoesntMatter

        val config = object : Configuration() {
            override fun getAppConfigurationEntry(name: String): Array<AppConfigurationEntry> {
                return arrayOf(
                        AppConfigurationEntry(
                                ReallyDoesntMatter::class.java.name,
                                AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
                                hashMapOf<String,Any>("username" to "srvkafkabroker", "password" to "broker")
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