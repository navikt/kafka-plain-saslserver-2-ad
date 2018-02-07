package org.navit.common.security.ldap

import com.unboundid.ldap.sdk.LDAPException
import com.unboundid.ldap.sdk.ResultCode
import org.slf4j.Logger
import org.slf4j.LoggerFactory

/**
 * A class verifying username and password through simple LDAP bind
 * See test/resources/adconfig.yaml for class parameters
 */

class LDAPAuthentication private constructor(
        host: String,
        port: Int,
        connectTimeout: Int,
        private val usrBaseDN: String,
        private val usrUid: String) : LDAPBase(host, port, connectTimeout)  {

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

        fun init(configFile: String): LDAPAuthentication = getConfig(configFile).let {
            when (it.isEmpty()) {
                true -> LDAPAuthentication("", 0, 0, "", "")
                else -> LDAPAuthentication(
                        it["host"].toString(),
                        try { it["port"]?.toInt() ?: 0 } catch (e: NumberFormatException) { 0 },
                        try { it["connTimeout"]?.toInt() ?: 10000 } catch (e: NumberFormatException) { 10000 },
                        it["usrBaseDN"].toString(),
                        it["usrUid"].toString()
                )
            }
        }
    }
}