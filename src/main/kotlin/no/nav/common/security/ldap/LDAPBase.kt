package no.nav.common.security.ldap

import com.unboundid.ldap.sdk.LDAPConnectionOptions
import com.unboundid.ldap.sdk.LDAPConnection
import com.unboundid.ldap.sdk.LDAPException
import com.unboundid.ldap.sdk.DisconnectType
import com.unboundid.ldap.sdk.PLAINBindRequest
import com.unboundid.ldap.sdk.ResultCode
import com.unboundid.util.ssl.SSLUtil
import com.unboundid.util.ssl.TrustAllTrustManager
import no.nav.common.security.AuthenticationResult
import no.nav.common.security.Monitoring
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import kotlin.system.measureTimeMillis

/**
 * A base class for LDAPAuthentication and LDAPAuthorization
 */

open class LDAPBase(config: LDAPConfig.Config = LDAPConfig.getByClasspath()) : AutoCloseable {

    private val connectOptions = LDAPConnectionOptions().apply { connectTimeoutMillis = config.connTimeout }

    // NB! - TrustAllTrustManager is too trusty, but good enough when inside corporate inner zone
    protected val ldapConnection = LDAPConnection(SSLUtil(TrustAllTrustManager()).createSSLSocketFactory(), connectOptions)
            .apply {
                try {
                    measureTimeMillis { connect(config.host, config.port) }
                            .also {
                                log.debug("Successfully connected to (${config.host},${config.port})")
                                log.info("${Monitoring.LDAP_BASE_TIME.txt} $it")
                            }
                } catch (e: LDAPException) {
                    log.error("${Monitoring.LDAP_BASE_FAILURE.txt} (${config.host},${config.port}) - ${e.diagnosticMessage}")
                    setDisconnectInfo(
                            DisconnectType.IO_ERROR,
                            "Exception when connecting to LDAP(${config.host},${config.port})", e)
                }
            }

    override fun close() {
        log.debug("Closing ldap connection")
        ldapConnection.close()
    }

    fun authenticationOk(username: String, pwd: String): AuthenticationResult =
            if (!ldapConnection.isConnected)
                AuthenticationResult.NoLDAPConnection
            else
                try {
                    log.debug("Trying bind for $username and given password")
                    ldapConnection.bind(PLAINBindRequest("u:$username", pwd)).let { bindResult ->
                        when (bindResult.resultCode) {
                            ResultCode.SUCCESS -> AuthenticationResult.SuccessfulBind
                            else -> AuthenticationResult.UnsuccessfulBind(
                                    "LDAP bind unsuccessful for $username - ${bindResult.diagnosticMessage}")
                        }
                    }
                } catch (e: LDAPException) {
                    AuthenticationResult.UnsuccessfulBind(
                            "LDAP bind exception for $username - ${e.diagnosticMessage}")
                }

    companion object {

        private val log: Logger = LoggerFactory.getLogger(LDAPBase::class.java)
    }
}