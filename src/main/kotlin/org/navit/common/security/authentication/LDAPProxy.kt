package org.navit.common.security.authentication

import com.unboundid.ldap.sdk.*
import com.unboundid.util.ssl.SSLUtil
import com.unboundid.util.ssl.TrustAllTrustManager
import org.slf4j.LoggerFactory
import org.yaml.snakeyaml.Yaml
import java.io.*


class LDAPProxy private constructor(
        val host: String,
        val port: Int,
        private val usrBaseDN: String,
        private val usrUid: String,
        private val grpBaseDN: String,
        private val grpUid: String,
        private val grpAttrName: String,
        bindDN: String,
        bindPwd: String) {

    //TODO  - TrustAllTrustManager is too trusty...
    private val ldapConnection = LDAPConnection(SSLUtil(TrustAllTrustManager()).createSSLSocketFactory())
    private val ldapCache = LDAPCache

    init {

        try {
            ldapConnection.connect(host, port)
            log.info("Successfully connected to ($host,$port)")
        }
        catch (e: LDAPException) {
            log.error("Authentication will fail! Exception when connecting to ($host,$port) - ${e.diagnosticMessage}")
            ldapConnection.setDisconnectInfo(DisconnectType.IO_ERROR,"Exception when connecting to LDAP($host,$port)", e)
        }

        try {
            //must perform binding for function isUserMemberOfAny
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
                            log.info("Bind cache updated")
                        }
                        getKafkaGroups()
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

        var result = false
        val userDN = "$usrUid=$user,$usrBaseDN"

        groups.forEach {

            val groupDN = "$grpUid=$it,$grpBaseDN"

            when(ldapCache.alreadyGrouped(groupDN,userDN)) {
                true -> {
                    result = true
                    log.info("[$it,$user] is cached")
                }
                else -> {
                    log.info("Trying compare-matched for $groupDN - $grpAttrName - $userDN")
                    result = result || try {
                        ldapConnection.compare(CompareRequest(groupDN, grpAttrName, userDN)).compareMatched().let {
                            getKafkaGroups()
                            it
                        }
                    }
                    catch(e: LDAPException) {
                        log.error("Compare-matched exception - invalid group!, ${e.exceptionMessage}")
                        false
                    }
                }
            }
        }

        return result
    }

    private fun getKafkaGroups() {

        val filter = Filter.createSubstringFilter(grpUid,"kt",null, null)

        try {
            val sResult = ldapConnection.search(SearchRequest(grpBaseDN, SearchScope.SUB, filter, grpAttrName))

            sResult.searchEntries.forEach {

                val groupDN = it.dn

                it.attributes.forEach {
                    it.values.forEach {
                        ldapCache.getGrouped(groupDN, it)
                    }
                }
            }
        }
        catch (e: LDAPSearchException) {
            log.error("Search exception - ${e.exceptionMessage}")
        }

        log.info("Group cache updated")
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
                        adConfig["grpAttrName"].toString(),
                        adConfig["bindDN"].toString(),
                        adConfig["bindPwd"].toString()
                )
            }
            else { //defaulting to connection error in case of no config YAML
                LDAPProxy("",0,"","","","","","","")
            }
        }
    }
}