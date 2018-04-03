package no.nav.common.security.ldap

import com.unboundid.ldap.sdk.LDAPException
import com.unboundid.ldap.sdk.ResultCode
import org.slf4j.Logger
import org.slf4j.LoggerFactory

/**
 * A class verifying username and password through simple LDAP bind
 */

class LDAPAuthentication private constructor(val config: LDAPConfig.Config) : LDAPBase(config) {

    override fun canUserAuthenticate(user: String, pwd: String): Boolean {

        // fair to disable authentication if no connection to ldap, even if the cache is operational
        if (!ldapConnection.isConnected) return false

        val userDN = "${config.usrUid}=$user,${config.usrBaseDN}"

        // service accounts created with self service solution BASTA is placed in ApplAccounts
        // just under ServiceAccounts, thus
        val userDNBasta = "${config.usrUid}=$user,ou=ApplAccounts,${config.usrBaseDN}"

        return when (LDAPCache.alreadyBounded(userDN, pwd) || LDAPCache.alreadyBounded(userDNBasta, pwd)) {
            true -> {
                log.info("$user is cached")
                true
            }
            else -> {
                log.info("Trying bind for $userDN/$userDNBasta and given password")

                val bindOk = try {
                    (ldapConnection.bind(userDN, pwd).resultCode == ResultCode.SUCCESS).let {
                        if (it) {
                            LDAPCache.getBounded(userDN, pwd)
                            log.info("Bind cache updated for $user")
                        }
                        it
                    }
                }
                catch(e: LDAPException) { false }

                val bindBastaOk = try {
                    (ldapConnection.bind(userDNBasta, pwd).resultCode == ResultCode.SUCCESS).let {
                        if (it) {
                            LDAPCache.getBounded(userDNBasta, pwd)
                            log.info("Bind cache updated for $user")
                        }
                        it
                    }

                }
                catch(e: LDAPException) { false }

                bindOk || bindBastaOk
            }
        }
    }

    companion object {

        private val log: Logger = LoggerFactory.getLogger(LDAPAuthentication::class.java)

        fun init(configFile: String = ""): LDAPAuthentication = when(configFile.isEmpty()) {
            true -> LDAPAuthentication(LDAPConfig.getByClasspath())
            else -> LDAPAuthentication(LDAPConfig.getBySource(configFile))
        }
    }
}