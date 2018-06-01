package no.nav.common.security.common

import com.unboundid.ldap.listener.InMemoryDirectoryServer
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig
import com.unboundid.ldap.listener.InMemoryListenerConfig
import com.unboundid.ldap.sdk.OperationType
import com.unboundid.util.ssl.KeyStoreKeyManager
import com.unboundid.util.ssl.SSLUtil
import com.unboundid.util.ssl.TrustAllTrustManager
import com.unboundid.util.ssl.TrustStoreTrustManager

/**
 * An object creating a in-memory LDAP server
 * - using LDAPS
 * - not allowing anonymous access to compare, thus, must bind first
 * - a baseDN that is enriched with resource/UserAndGroups.ldif
 * - start and stop functions to be used before/after test cases
 */

object InMemoryLDAPServer {

    private val imConf = InMemoryDirectoryServerConfig("dc=example,dc=com", "dc=adeo,dc=example,dc=com")

    private const val KStore = "src/test/resources/inmds.jks"
    private val tlsCF = SSLUtil(TrustAllTrustManager()).createSSLSocketFactory()
    private val tlsSF = SSLUtil(
            KeyStoreKeyManager(KStore, "password".toCharArray(), "JKS", "inmds"),
            TrustStoreTrustManager(KStore))
            .createSSLServerSocketFactory()

    private val imDS: InMemoryDirectoryServer

    init {

        imConf.setListenerConfigs(
                InMemoryListenerConfig.createLDAPConfig("LDAP", 11389),
                InMemoryListenerConfig.createLDAPSConfig("LDAPS", null, 11636, tlsSF, tlsCF)
        )
        // must bind before compare, equal to non-anonymous access./
        imConf.setAuthenticationRequiredOperationTypes(OperationType.COMPARE)

        imDS = InMemoryDirectoryServer(imConf)
        imDS.importFromLDIF(true, "src/test/resources/UsersAndGroups.ldif")
    }

    fun start() {
        imDS.startListening("LDAP")
        imDS.startListening("LDAPS")
    }

    fun stop() {
        imDS.shutDown(true)
    }
}