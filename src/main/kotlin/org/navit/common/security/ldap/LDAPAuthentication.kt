package org.navit.common.security.ldap

import com.unboundid.ldap.sdk.LDAPException
import com.unboundid.ldap.sdk.ResultCode
import org.slf4j.Logger
import org.slf4j.LoggerFactory

/**
 * A class verifying username and password through simple LDAP bind
 * See test/resources/adconfig.yaml for class parameters
 */

class LDAPAuthentication private constructor(map: Map<String, Any?>) : LDAPBase(map) {
        private val usrBaseDN: String by map
        private val usrUid: String by map

    override fun canUserAuthenticate(user: String, pwd: String): Boolean {

        // fair to disable authentication if no connection to ldap, even if the cache is operational
        if (!ldapConnection.isConnected) return false

        return try {

            val userDN = "$usrUid=$user,$usrBaseDN"

            when (ldapCache.alreadyBounded(userDN, pwd)) {
                true -> {
                    log.info("$user is cached")
                    true
                }
                else -> {
                    log.info("Trying bind for $userDN and given password")
                    (ldapConnection.bind(userDN, pwd).resultCode == ResultCode.SUCCESS).let {
                        if (it) {
                            ldapCache.getBounded(userDN, pwd)
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
            false -> LDAPAuthentication(ADConfig.getBySource(configFile))
        }
    }
}