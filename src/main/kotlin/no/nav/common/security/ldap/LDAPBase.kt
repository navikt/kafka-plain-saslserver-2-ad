package no.nav.common.security.ldap

import com.unboundid.ldap.sdk.LDAPConnectionOptions
import com.unboundid.ldap.sdk.LDAPConnection
import com.unboundid.ldap.sdk.LDAPException
import com.unboundid.ldap.sdk.DisconnectType
import com.unboundid.ldap.sdk.PLAINBindRequest
import com.unboundid.ldap.sdk.ResultCode
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
            measureTimeMillis { ldapConnection.connect(config.host, config.port) }
                    .also {
                        log.debug("Successfully connected to (${config.host},${config.port})")
                        log.info("${Monitoring.LDAP_BASE_TIME.txt} $it")
                    }
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

    protected fun bindOk(username: String, pwd: String): Boolean =
            try {
                log.debug("Trying bind for $username and given password")
                when (ldapConnection.bind(PLAINBindRequest("u:$username", pwd)).resultCode) {
                    ResultCode.SUCCESS -> true
                    else -> false.also { log.error("LDAP bind unsuccessful for $username - unknown situation :-(") }
                }
            } catch (e: LDAPException) {
                false.also { log.error("LDAP bind exception for $username - ${e.diagnosticMessage}") }
            }

    open fun canUserAuthenticate(username: String, pwd: String): Boolean = false

    data class AuthorResult(val groupName: String, val user: String)

    open fun isUserMemberOfAny(username: String, groups: List<String>): Set<AuthorResult> = emptySet()

    companion object {

        private val log: Logger = LoggerFactory.getLogger(LDAPBase::class.java)
    }
}