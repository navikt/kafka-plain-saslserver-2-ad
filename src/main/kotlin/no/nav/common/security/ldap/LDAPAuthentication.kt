package no.nav.common.security.ldap

import com.unboundid.ldap.sdk.LDAPException
import com.unboundid.ldap.sdk.ResultCode
import org.slf4j.Logger
import org.slf4j.LoggerFactory

/**
 * A class verifying username and password through simple LDAP bind
 */

class LDAPAuthentication private constructor(val config: LDAPConfig.Config) : LDAPBase(config) {

    private fun bindOk(user: String, pwd: String): AuthenResult =
            try {
                if (ldapConnection.bind(user, pwd).resultCode == ResultCode.SUCCESS)
                    AuthenResult(true, user)
                else
                    AuthenResult(false, "")
            } catch (e: LDAPException) {
                AuthenResult(false, "")
            }

    override fun canUserAuthenticate(user: String, pwd: String): AuthenResult =

        if (!ldapConnection.isConnected)
            AuthenResult(false, "")
        else {
            val userDN = config.toUserDN(user)
            val userDNBasta = config.toUserDNBasta(user)

            log.debug("Trying bind for $userDN/$userDNBasta and given password")

            // as long as at least one user DN can authenticate, no error report in log
            listOf(userDN, userDNBasta)
                    .fold(AuthenResult(false, "")) { res, uDN -> res.combine(bindOk(uDN, pwd)) }
        }

    companion object {

        private val log: Logger = LoggerFactory.getLogger(LDAPAuthentication::class.java)

        fun init(configFile: String = ""): LDAPAuthentication = when (configFile.isEmpty()) {
            true -> LDAPAuthentication(LDAPConfig.getByClasspath())
            else -> LDAPAuthentication(LDAPConfig.getBySource(configFile))
        }
    }
}