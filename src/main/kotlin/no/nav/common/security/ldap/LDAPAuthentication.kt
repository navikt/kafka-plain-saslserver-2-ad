package no.nav.common.security.ldap

import com.unboundid.ldap.sdk.LDAPException
import com.unboundid.ldap.sdk.ResultCode
import org.slf4j.Logger
import org.slf4j.LoggerFactory

/**
 * A class verifying username and password through simple LDAP bind
 */

class LDAPAuthentication private constructor(val config: LDAPConfig.Config) : LDAPBase(config) {

    private fun bindOk(user: String, pwd: String) : Boolean =
            try {
                if (ldapConnection.bind(user, pwd).resultCode == ResultCode.SUCCESS) {
                    LDAPCache.getBounded(user, pwd)
                    log.info("Bind cache updated for $user")
                    true
                }
                else false
            }
            catch(e: LDAPException) { false }

    override fun canUserAuthenticate(user: String, pwd: String): Boolean =

        if (!ldapConnection.isConnected)
            false
        else {
            val userDN = config.toUserDN(user)
            val userDNBasta = config.toUserDNBasta(user)

            log.debug("Trying bind for $userDN/$userDNBasta and given password")

            listOf(userDN, userDNBasta).fold(false, {res, uDN -> res || bindOk(uDN,pwd)})
        }

    companion object {

        private val log: Logger = LoggerFactory.getLogger(LDAPAuthentication::class.java)

        fun init(configFile: String = ""): LDAPAuthentication = when(configFile.isEmpty()) {
            true -> LDAPAuthentication(LDAPConfig.getByClasspath())
            else -> LDAPAuthentication(LDAPConfig.getBySource(configFile))
        }
    }
}