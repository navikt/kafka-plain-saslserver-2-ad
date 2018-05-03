package no.nav.common.security.ldap

import com.unboundid.ldap.sdk.*
import org.slf4j.Logger
import org.slf4j.LoggerFactory

/**
 * A class verifying group membership with LDAP compare-matched
 */

class LDAPAuthorization private constructor(val config: LDAPConfig.Config) : LDAPBase(config) {

    // In authorization context, needs to bind the connection before compare-match between group and user
    // due to no anonymous access allowed for LDAP operations like search, compare, ...
    private val bindDN = config.toUserDN(JAASContext.username)
    private val bindPwd = JAASContext.password

    init {
        log.debug("Binding information for authorization fetched from JAAS config file [$bindDN]")

        try {
            ldapConnection.bind(bindDN,bindPwd)
            log.debug("Successfully bind to (${config.host},${config.port}) with $bindDN")
        }
        catch (e: LDAPException) {
            log.error("Authorization will fail! " +
                    "Exception during bind of $bindDN to (${config.host},${config.port}) - ${e.diagnosticMessage}")
        }
    }

    private fun getGroupDN(groupName: String): String =
            try{
                val filter = Filter.createEqualityFilter(config.grpUid, groupName)

                ldapConnection
                        .search(SearchRequest(config.grpBaseDN, SearchScope.SUB, filter, SearchRequest.NO_ATTRIBUTES))
                        .let {
                            if (it.entryCount == 1)
                                it.searchEntries[0].dn
                            else
                                ""
                        }
            }
            catch (e: LDAPSearchException){
                log.error("Cannot find group $groupName under ${config.grpBaseDN}")
                ""
            }

    private fun userInGroup(userDN: String, groupName: String, uuid: String): Boolean =
            try {

                val groupDN = getGroupDN(groupName)

                log.debug("Trying compare-matched for $groupDN - ${config.grpAttrName} - $userDN ($uuid)")

                ldapConnection
                        .compare(CompareRequest(groupDN, config.grpAttrName, userDN))
                        .compareMatched()
                        .let {
                            if (it) {
                                LDAPCache.getGrouped(groupName, userDN)
                                log.info("Group cache updated for [$groupName,$userDN] ($uuid)")
                            }
                            it
                        }
            }
            catch(e: LDAPException) {
                log.error("Compare-matched exception - invalid group!, ${e.exceptionMessage} ($uuid)")
                false
            }

    override fun isUserMemberOfAny(user: String, groups: List<String>, uuid: String): Boolean =

            if (!ldapConnection.isConnected)
                false
            else {
                val userDN = config.toUserDN(user)
                val userDNBasta = config.toUserDNBasta(user)

                groups.fold(false, {res, groupName ->
                    res || userInGroup(userDN, groupName, uuid) || userInGroup(userDNBasta, groupName, uuid) })
            }

    companion object {

        private val log: Logger = LoggerFactory.getLogger(LDAPAuthorization::class.java)

        fun init(configFile: String = ""): LDAPAuthorization = when(configFile.isEmpty()) {
            true -> LDAPAuthorization(LDAPConfig.getByClasspath())
            else -> LDAPAuthorization(LDAPConfig.getBySource(configFile))
        }
    }
}