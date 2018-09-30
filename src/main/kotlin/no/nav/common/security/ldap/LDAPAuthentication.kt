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
                    AuthenResult(true, user, "")
                else {
                    AuthenResult(false, user, "LDAP bind unsuccessful for $user - unknown situation :-(")
                }
            } catch (e: LDAPException) {
                AuthenResult(false, user, "LDAP bind exception for $user - ${e.diagnosticMessage}")
            }

    private fun userNodesBindOk(userNodes: List<String>, pwd: String): AuthenResult =
        // as long as at least one user DN can authenticate, no error report in log
        userNodes.map { uDN -> bindOk(uDN, pwd) }.let { result ->
            if (result.any { it.authenticated })
                result.first { it.authenticated }
            else {
                result.forEach { log.error(it.errMsg) }
                result.first { !it.authenticated }
            }
        }

    override fun canUserAuthenticate(user: String, pwd: String): AuthenResult =
        if (!ldapConnection.isConnected) {
            log.error("No LDAP connection, cannot authenticate $user and related password!")
            AuthenResult(false, "", "")
        } else {
            val userNodes = config.toUserDNNodes(user)
            log.debug("Trying bind for $userNodes and given password")
            userNodesBindOk(userNodes, pwd)
        }

    companion object {

        private val log: Logger = LoggerFactory.getLogger(LDAPAuthentication::class.java)

        fun init(configFile: String = ""): LDAPAuthentication = when (configFile.isEmpty()) {
            true -> LDAPAuthentication(LDAPConfig.getByClasspath())
            else -> LDAPAuthentication(LDAPConfig.getBySource(configFile))
        }
    }
}