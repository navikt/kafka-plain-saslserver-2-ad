package no.nav.common.security.ldap

import no.nav.common.security.Monitoring
import org.slf4j.Logger
import org.slf4j.LoggerFactory

/**
 * A class verifying username and password through simple LDAP bind
 */

class LDAPAuthentication private constructor(val config: LDAPConfig.Config) : LDAPBase(config) {

    override fun canUserAuthenticate(username: String, pwd: String): Boolean =
        if (!ldapConnection.isConnected) false
                .also { log.error("${Monitoring.AUTHENTICATION_LDAP_FAILURE.txt} $username and related password!") }
        else
            bindOk(username, pwd)

    companion object {

        private val log: Logger = LoggerFactory.getLogger(LDAPAuthentication::class.java)

        fun init(configFile: String = ""): LDAPAuthentication = when (configFile.isEmpty()) {
            true -> LDAPAuthentication(LDAPConfig.getByClasspath())
            else -> LDAPAuthentication(LDAPConfig.getBySource(configFile))
        }
    }
}