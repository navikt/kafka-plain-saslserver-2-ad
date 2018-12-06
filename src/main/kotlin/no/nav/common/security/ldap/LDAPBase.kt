package no.nav.common.security.ldap

import com.unboundid.ldap.sdk.LDAPConnectionOptions
import com.unboundid.ldap.sdk.LDAPConnection
import com.unboundid.ldap.sdk.LDAPException
import com.unboundid.ldap.sdk.DisconnectType
import com.unboundid.util.ssl.SSLUtil
import com.unboundid.util.ssl.TrustAllTrustManager
import no.nav.common.security.Monitoring
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import kotlin.system.measureTimeMillis

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
            val connTime = measureTimeMillis { ldapConnection.connect(config.host, config.port) }
            log.debug("Successfully connected to (${config.host},${config.port})")
            log.info("${Monitoring.LDAP_BASE_TIME.txt} $connTime")
        } catch (e: LDAPException) {
            log.error("${Monitoring.LDAP_BASE_FAILURE.txt} (${config.host},${config.port}) - ${e.diagnosticMessage}")
            ldapConnection.setDisconnectInfo(
                    DisconnectType.IO_ERROR,
                    "Exception when connecting to LDAP(${config.host},${config.port})", e)
        }
    }

    override fun close() {
        log.debug("Closing ldap connection")
        ldapConnection.close()
    }

    data class AuthenResult(val authenticated: Boolean, val userDN: String, val errMsg: String)

    open fun canUserAuthenticate(userDNs: List<String>, pwd: String): Set<AuthenResult> = emptySet()

    data class AuthorResult(val groupName: String, val userDN: String)

    open fun isUserMemberOfAny(userDNs: List<String>, groups: List<String>): Set<AuthorResult> = emptySet()

    companion object {

        private val log: Logger = LoggerFactory.getLogger(LDAPBase::class.java)
    }
}