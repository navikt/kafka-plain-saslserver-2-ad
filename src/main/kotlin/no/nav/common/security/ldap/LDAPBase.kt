package no.nav.common.security.ldap

import com.unboundid.ldap.sdk.LDAPConnectionOptions
import com.unboundid.ldap.sdk.LDAPConnection
import com.unboundid.ldap.sdk.LDAPException
import com.unboundid.ldap.sdk.DisconnectType
import com.unboundid.util.ssl.SSLUtil
import com.unboundid.util.ssl.TrustAllTrustManager
import org.slf4j.Logger
import org.slf4j.LoggerFactory

/**
 * A base class for LDAPAuthentication and LDAPAuthorization
 */

abstract class LDAPBase protected constructor(config: LDAPConfig.Config) : AutoCloseable {

    private val connectOptions = LDAPConnectionOptions().apply {
        connectTimeoutMillis = config.connTimeout
    }

    // NB! - TrustAllTrustManager is too trusty, but good enough when inside corporate inner zone
    protected val ldapConnection = LDAPConnection(
            SSLUtil(TrustAllTrustManager()).createSSLSocketFactory(),
            connectOptions)

    init {
        // initialize LDAP connection
        try {
            ldapConnection.connect(config.host, config.port)
            log.debug("Successfully connected to (${config.host},${config.port})")
        } catch (e: LDAPException) {
            log.error("Authentication and authorization will fail! " +
                    "Exception when connecting to (${config.host},${config.port}) - ${e.diagnosticMessage}")
            ldapConnection.setDisconnectInfo(
                    DisconnectType.IO_ERROR,
                    "Exception when connecting to LDAP(${config.host},${config.port})", e)
        }
    }

    override fun close() {
        log.debug("Closing ldap connection")
        ldapConnection.close()
    }

    data class AuthenResult(val authenticated: Boolean, val userDN: String)

    // assuming that a service user cannot be 2 places in LDAP hierarchy
    fun AuthenResult.combine(other: AuthenResult): AuthenResult =
            AuthenResult(
                    this.authenticated || other.authenticated,
                    this.userDN + other.userDN)

    open fun canUserAuthenticate(user: String, pwd: String): AuthenResult = AuthenResult(false, "")

    data class AuthorResult(val groupName: String, val userDN: String)

    open fun isUserMemberOfAny(user: String, groups: List<String>, uuid: String): Set<AuthorResult> = emptySet()

    companion object {

        private val log: Logger = LoggerFactory.getLogger(LDAPBase::class.java)
    }
}