package org.navit.common.security.ldap

import com.unboundid.ldap.sdk.*
import com.unboundid.util.ssl.SSLUtil
import com.unboundid.util.ssl.TrustAllTrustManager
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.yaml.snakeyaml.Yaml
import java.io.File
import java.io.FileInputStream
import java.io.FileNotFoundException

/**
 * A base class for LDAPAuthentication and LDAPAuthorization
 */

abstract class LDAPBase protected constructor(host: String, port: Int, connectTimeout: Int) {

    //TODO  - TrustAllTrustManager is too trusty, but good enough when inside corporate inner zone
    protected val ldapConnection: LDAPConnection
    private val connectOptions = LDAPConnectionOptions()
    protected val ldapCache = LDAPCache

    init {
        // initialize LDAP connection

        connectOptions.connectTimeoutMillis = connectTimeout
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

        const val CONFIGFILE = "adconfig.yaml"
        private val log: Logger = LoggerFactory.getLogger(LDAPBase::class.java)

        fun getConfig(configFile: String): Map<String, String> {

            return if (!configFile.isEmpty()) {
                try {
                    Yaml().load<Map<String, *>>(FileInputStream(File(configFile))).let {

                        var newMap = emptyMap<String, String>()
                        it.forEach { newMap += Pair(it.key,it.value?.toString() ?: "") }
                        newMap
                    }
                } catch (e: FileNotFoundException) {
                    emptyMap<String, String>()
                }
            }
            else { //defaulting to connection error in case of no config YAML
                emptyMap()
            }
        }
    }
}