package org.navit.common.security.ldap

import com.unboundid.ldap.sdk.*
import com.unboundid.util.ssl.SSLUtil
import com.unboundid.util.ssl.TrustAllTrustManager
import org.slf4j.Logger
import org.slf4j.LoggerFactory

/**
 * A base class for LDAPAuthentication and LDAPAuthorization
 */

abstract class LDAPBase protected constructor(map: Map<String, Any?>) {
        protected val host: String by map
        protected val port: Int by map
        protected val connTimeout: Int by map

    //TODO  - TrustAllTrustManager is too trusty, but good enough when inside corporate inner zone
    protected val ldapConnection: LDAPConnection
    private val connectOptions = LDAPConnectionOptions()
    protected val ldapCache = LDAPCache

    init {
        // initialize LDAP connection

        connectOptions.connectTimeoutMillis = connTimeout
        ldapConnection =  LDAPConnection(SSLUtil(TrustAllTrustManager()).createSSLSocketFactory(),connectOptions)

        try {
            ldapConnection.connect(host, port)
            log.info("Successfully connected to ($host,$port)")
        }
        catch (e: LDAPException) {
            log.error("Authentication and authorization will fail! Exception when connecting to ($host,$port) - ${e.diagnosticMessage}")
            ldapConnection.setDisconnectInfo(DisconnectType.IO_ERROR,"Exception when connecting to LDAP($host,$port)", e)
        }
    }

    open fun canUserAuthenticate(user: String, pwd: String): Boolean = false

    open fun isUserMemberOfAny(user: String, groups: List<String>): Boolean = false

    companion object {

        private val log: Logger = LoggerFactory.getLogger(LDAPBase::class.java)
    }
}