package org.navit.common.security.ldap

import com.unboundid.ldap.sdk.CompareRequest
import com.unboundid.ldap.sdk.LDAPException
import org.slf4j.Logger
import org.slf4j.LoggerFactory

/**
 * A class verifying group membership with LDAP compare-matched
 * See test/resources/adconfig.yaml for class parameters
 */

class LDAPAuthorization private constructor(
        host: String,
        port: Int,
        connectTimeout: Int,
        private val usrBaseDN: String,
        private val usrUid: String,
        private val grpBaseDN: String,
        private val grpUid: String,
        private val grpAttrName: String) : LDAPBase(host, port, connectTimeout) {

    // extracting JAAS context from kafka server - prerequisite is  PLAINSASL context

    private val jaasContext = object {

        val username: String
        val password: String

        init {

            val options: Map<String,String> = try {
                val jaasFile = javax.security.auth.login.Configuration.getConfiguration()
                val entries = jaasFile.getAppConfigurationEntry("KafkaServer")
                entries?.get(0)?.options?.let { it.map { Pair<String,String>(it.key,it.value.toString()) }.toMap() } ?: emptyMap()
            }
            catch (e: SecurityException) {
                log.error("JAAS read exception - ${e.message}")
                emptyMap()
            }

            username = options["username"].toString()
            password = options["password"].toString()
        }
    }

    // In authorization context, needs to bind the connection before compare-match between group and user
    // due to no anonymous access allowed for LDAP operations like search, compare, ...
    private val bindDN = "$usrUid=${jaasContext.username},$usrBaseDN"
    private val bindPwd = jaasContext.password

    init {
        log.info("Binding information for authorization fetched from JAAS config file [$bindDN]")

        try {
            ldapConnection.bind(bindDN,bindPwd)
            log.info("Successfully bind to ($host,$port) with $bindDN")
        }
        catch (e: LDAPException) {
            log.error("Authorization will fail! Exception when bind to ($host,$port) - ${e.diagnosticMessage}")
        }
    }

    override fun isUserMemberOfAny(user: String, groups: List<String>): Boolean {

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

        private val log: Logger = LoggerFactory.getLogger(LDAPAuthorization::class.java)

        fun init(configFile: String) : LDAPAuthorization {

            return getConfig(configFile).let {

                if (!it.isEmpty())
                    LDAPAuthorization(
                            it["host"].toString(),
                            try {it["port"]?.toInt() ?: 0} catch (e: NumberFormatException){0},
                            try {it["connTimeout"]?.toInt() ?: 10000} catch (e: NumberFormatException){10000},
                            it["usrBaseDN"].toString(),
                            it["usrUid"].toString(),
                            it["grpBaseDN"].toString(),
                            it["grpUid"].toString(),
                            it["grpAttrName"].toString()
                    )
                else
                    LDAPAuthorization("", 0, 0,
                            "", "", "", "","")
            }
        }
    }

}