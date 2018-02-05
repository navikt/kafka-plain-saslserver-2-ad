package org.navit.common.security.authentication

import com.unboundid.ldap.sdk.*
import com.unboundid.util.ssl.SSLUtil
import com.unboundid.util.ssl.TrustAllTrustManager
import org.slf4j.LoggerFactory
import org.yaml.snakeyaml.Yaml
import java.io.*

/**
 *
 *  LDAPProxy is used in two different contexts
 * - Authentication as part of PlainSaslServer.evaluateResponse - see canUserAuthenticate
 * - Authorization as part of LDAPAuthorizer via NAVAuthorizer - see isUserMemberOfAny
 *
 */

class LDAPProxy private constructor(
        host: String,
        port: Int,
        private val usrBaseDN: String,
        private val usrUid: String,
        private val grpBaseDN: String,
        private val grpUid: String,
        private val grpAttrName: String) {

    object JAASContext {

        val username: String
        val password: String

        init {

            var options = mutableMapOf<String,Any>()

            try {
                val jaasFile = javax.security.auth.login.Configuration.getConfiguration()
                val entries = jaasFile.getAppConfigurationEntry("KafkaServer")
                options = entries?.get(0)?.options as MutableMap<String, Any>
            }
            catch (e: SecurityException) {
                log.error("JAAS read exception - ${e.message}")
            }

            username = options["username"].toString()
            password = options["password"].toString()
        }
    }

    //TODO  - TrustAllTrustManager is too trusty...
    private val ldapConnection = LDAPConnection(SSLUtil(TrustAllTrustManager()).createSSLSocketFactory())
    private val ldapCache = LDAPCache

    // In authorization context, needs to bind the connection before compare-match between group and user
    // due to no anonymous access allowed for LDAP operations like search, compare, ...
    private val bindDN = "$usrUid=${JAASContext.username},$usrBaseDN"
    private val bindPwd = JAASContext.password

    init {
        log.info("Binding information for authorization fetched from JAAS config file [$bindDN]")

        // initialize LDAP connection
        try {
            ldapConnection.connect(host, port)
            log.info("Successfully connected to ($host,$port)")
        }
        catch (e: LDAPException) {
            log.error("Authentication and authorization will fail! Exception when connecting to ($host,$port) - ${e.diagnosticMessage}")
            ldapConnection.setDisconnectInfo(DisconnectType.IO_ERROR,"Exception when connecting to LDAP($host,$port)", e)
        }

        // perform binding before any invocations of isUserMemberOfAny - authorization context
        try {
            ldapConnection.bind(bindDN,bindPwd)
            log.info("Successfully bind to ($host,$port) with $bindDN")
        }
        catch (e: LDAPException) {
            log.error("Authorization will fail! Exception when bind to ($host,$port) - ${e.diagnosticMessage}")
        }
    }

    fun canUserAuthenticate(user: String, pwd: String): Boolean {

        // fair to disable authentication if no connection to ldap, even if the cache is operational
        if (!ldapConnection.isConnected) return false

        return try {

            val userDN = "$usrUid=$user,$usrBaseDN"

            when (ldapCache.alreadyBounded(userDN, pwd)) {
                true -> {
                    log.info("$user is cached")
                    true
                }
                else -> {
                    log.info("Trying bind for $userDN and given password")
                    (ldapConnection.bind(userDN, pwd).resultCode == ResultCode.SUCCESS).let {
                        if (it) {
                            ldapCache.getBounded(userDN, pwd)
                            log.info("Bind cache updated for $user")
                        }
                        it
                    }
                }
            }
        }
        catch(e: LDAPException) {
            log.error("Bind exception, ${e.exceptionMessage}")
            false
        }
    }

    fun isUserMemberOfAny(user: String, groups: List<String>): Boolean {

        var isMember: Boolean
        val userDN = "$usrUid=$user,$usrBaseDN"

        // check if group-user has at least one cache hit
        isMember =  groups.map { ldapCache.alreadyGrouped("$grpUid=$it,$grpBaseDN",userDN) }.indexOfFirst { it == true }.let {
            val found = (it >= 0)
            if (found) log.info("[${groups[it]},$user] is cached")
            found
        }

        if (isMember) return true

        groups.forEach {

            val groupDN = "$grpUid=$it,$grpBaseDN"
            val groupName = it

            log.info("Trying compare-matched for $groupDN - $grpAttrName - $userDN")
            isMember = isMember || try {
                ldapConnection.compare(CompareRequest(groupDN, grpAttrName, userDN)).compareMatched().let {
                    if (it) {
                        ldapCache.getGrouped(groupDN, userDN)
                        log.info("Group cache updated for [$groupName,$user")
                    }
                    it
                }
            }
            catch(e: LDAPException) {
                log.error("Compare-matched exception - invalid group!, ${e.exceptionMessage}")
                false
            }
        }

        return isMember
    }

    companion object {

        const val CONFIGFILE = "adconfig.yaml"
        private val log = LoggerFactory.getLogger(LDAPProxy::class.java)

        fun init(configFile: String) : LDAPProxy {

            return if (!configFile.isEmpty()) {

                val adConfig = try {
                    Yaml().load<Map<String, *>>(FileInputStream(File(configFile)))
                } catch (e: FileNotFoundException) {
                    emptyMap<String, String>()
                }

                LDAPProxy(
                        adConfig["host"].toString(),
                        adConfig["port"]?.toString()?.toInt() ?: 0,
                        adConfig["usrBaseDN"].toString(),
                        adConfig["usrUid"].toString(),
                        adConfig["grpBaseDN"].toString(),
                        adConfig["grpUid"].toString(),
                        adConfig["grpAttrName"].toString()
                )
            }
            else { //defaulting to connection error in case of no config YAML
                LDAPProxy("",0,"","","","","")
            }
        }
    }
}