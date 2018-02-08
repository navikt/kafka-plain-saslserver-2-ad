package no.nav.common.security.ldap

import com.unboundid.ldap.sdk.LDAPException
import com.unboundid.ldap.sdk.ResultCode
import org.slf4j.Logger
import org.slf4j.LoggerFactory

/**
 * A class verifying username and password through simple LDAP bind
 */

class LDAPAuthentication private constructor(val config: ADConfig.Config) : LDAPBase(config) {

    override fun canUserAuthenticate(user: String, pwd: String): Boolean {

        // fair to disable authentication if no connection to ldap, even if the cache is operational
        if (!ldapConnection.isConnected) return false

        return try {

            val userDN = "${config.usrUid}=$user,${config.usrBaseDN}"

            when (LDAPCache.alreadyBounded(userDN, pwd)) {
                true -> {
                    log.info("$user is cached")
                    true
                }
                else -> {
                    log.info("Trying bind for $userDN and given password")
                    (ldapConnection.bind(userDN, pwd).resultCode == ResultCode.SUCCESS).let {
                        if (it) {
                            LDAPCache.getBounded(userDN, pwd)
                            log.info("Bind cache updated for $user")
                        }
                        it
                    }
                }
            }
        }
        catch(e: LDAPException) {
            log.error("Bind exception, ${e.exceptionMessage}")
            false
        }
    }

    companion object {

        private val log: Logger = LoggerFactory.getLogger(LDAPAuthentication::class.java)

        fun init(configFile: String = ""): LDAPAuthentication = when(configFile.isEmpty()) {
            true -> LDAPAuthentication(ADConfig.getByClasspath())
            else -> LDAPAuthentication(ADConfig.getBySource(configFile))
        }
    }
}