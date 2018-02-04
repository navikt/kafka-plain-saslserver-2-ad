package org.navit.common.security.authentication

import com.unboundid.ldap.sdk.*
import org.slf4j.LoggerFactory
import org.yaml.snakeyaml.Yaml
import java.io.*

// Added
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

    private val ldapConnection = LDAPConnection()
    private val ldapCache = LDAPCache

    init {

        try {
            ldapConnection.connect(host, port)
            log.info("$ldapAuthentication successfully connected to ($host,$port)")
        }
        catch (e: LDAPException) {
            log.error("$ldapAuthentication authentication will fail! Exception when connecting to ($host,$port)")
            ldapConnection.setDisconnectInfo(DisconnectType.IO_ERROR,"Exception when connecting to LDAP($host,$port)", e)
        }

        try {
            //must perform binding for function isUserMemberOfAny
            ldapConnection.bind(bindDN,bindPwd)
            log.info("$ldapAuthentication successfully bind to ($host,$port) with $bindDN")
        }
        catch (e: LDAPException) {
            log.error("$ldapAuthentication authorization will fail! Exception when bind to ($host,$port) - ${e.diagnosticMessage}")
        }
    }

    fun canUserAuthenticate(user: String, pwd: String): Boolean {

        // fair to disable authentication if no connection to ldap, even if the cache is operational
        if (!ldapConnection.isConnected) return false

        return try {

            val userDN = "$usrUid=$user,$usrBaseDN"

            when (ldapCache.alreadyBinded(userDN, pwd)) {
                true -> {
                    log.info("$ldapAuthentication $userDN is cached")
                    true
                }
                else -> {
                    log.info("$ldapAuthentication trying bind for $userDN and given password")
                    (ldapConnection.bind(userDN, pwd).resultCode == ResultCode.SUCCESS).let {
                        if (it) ldapCache.getBinded(userDN, pwd)
                        getKafkaGroups()
                        it
                    }
                }
            }
        }
        catch(e: LDAPException) {
            log.error("$ldapAuthentication bind exception, ${e.exceptionMessage}")
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
                    log.info("$ldapAuthentication [$groupDN,$userDN] is cached")
                }
                else -> {
                    log.info("$ldapAuthentication trying compare-matched for $groupDN - $grpAttrName - $userDN")
                    result = result || try {
                        ldapConnection.compare(CompareRequest(groupDN, grpAttrName, userDN)).compareMatched()
                    }
                    catch(e: LDAPException) {
                        log.error("$ldapAuthentication compare-matched exception - invalid group!, ${e.exceptionMessage}")
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
            log.error("$ldapAuthentication search exception - ${e.exceptionMessage}")
        }
    }

    companion object {

        const val configFile = "adconfig.yaml"
        private val log = LoggerFactory.getLogger(LDAPProxy::class.java)
        private const val ldapAuthentication = "LDAP authentication:"

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