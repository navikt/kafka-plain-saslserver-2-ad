package no.nav.common.security.ldap

import com.unboundid.ldap.sdk.*
import com.unboundid.util.ssl.SSLUtil
import com.unboundid.util.ssl.TrustAllTrustManager
import org.slf4j.Logger
import org.slf4j.LoggerFactory

/**
 * A base class for LDAPAuthentication and LDAPAuthorization
 */

abstract class LDAPBase protected constructor(config: ADConfig.Config) {

    //TODO  - TrustAllTrustManager is too trusty, but good enough when inside corporate inner zone
    protected val ldapConnection: LDAPConnection
    private val connectOptions = LDAPConnectionOptions()
    protected val ldapCache = LDAPCache

    init {
        // initialize LDAP connection

        connectOptions.connectTimeoutMillis = config.connTimeout
        ldapConnection =  LDAPConnection(SSLUtil(TrustAllTrustManager()).createSSLSocketFactory(),connectOptions)

        try {
            ldapConnection.connect(config.host, config.port)
            log.info("Successfully connected to (${config.host},${config.port})")
        }
        catch (e: LDAPException) {
            log.error("Authentication and authorization will fail! " +
                    "Exception when connecting to (${config.host},${config.port}) - ${e.diagnosticMessage}")
            ldapConnection.setDisconnectInfo(
                    DisconnectType.IO_ERROR,
                    "Exception when connecting to LDAP(${config.host},${config.port})", e)
        }
    }

    open fun canUserAuthenticate(user: String, pwd: String): Boolean = false

    open fun isUserMemberOfAny(user: String, groups: List<String>): Boolean = false

    companion object {

        private val log: Logger = LoggerFactory.getLogger(LDAPBase::class.java)
    }
}