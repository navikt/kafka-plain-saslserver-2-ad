package no.nav.common.security.ldap

import com.unboundid.ldap.sdk.*
import org.slf4j.Logger
import org.slf4j.LoggerFactory

/**
 * A class verifying group membership with LDAP compare-matched
 */

class LDAPAuthorization private constructor(val config: LDAPConfig.Config) : LDAPBase(config) {

    // extracting JAAS context from kafka server - prerequisite is  PLAINSASL context

    private val jaasContext = object {

        val username: String
        val password: String

        init {

            val options: Map<String,String> = try {
                val jaasFile = javax.security.auth.login.Configuration.getConfiguration()
                val entries = jaasFile.getAppConfigurationEntry("KafkaServer")
                entries
                        ?.get(0)
                        ?.options
                        ?.let { it.map { Pair<String,String>(it.key, it.value.toString()) }.toMap() } ?: emptyMap()
            }
            catch (e: SecurityException) {
                log.error("JAAS read exception - ${e.message}")
                emptyMap()
            }

            username = options["username"].toString()
            password = options["password"].toString()
        }
    }

    private fun toUserDN(user: String) = "${config.usrUid}=$user,${config.usrBaseDN}"

    // must also consider BASTA created service users
    private fun toUserDNBasta(user: String) = "${config.usrUid}=$user,ou=ApplAccounts,${config.usrBaseDN}"

    //private fun toGroupDN(group: String) =  "${config.grpUid}=$group,${config.grpBaseDN}"

    // In authorization context, needs to bind the connection before compare-match between group and user
    // due to no anonymous access allowed for LDAP operations like search, compare, ...
    private val bindDN = toUserDN(jaasContext.username)
    private val bindPwd = jaasContext.password

    init {
        log.info("Binding information for authorization fetched from JAAS config file [$bindDN]")

        try {
            ldapConnection.bind(bindDN,bindPwd)
            log.info("Successfully bind to (${config.host},${config.port}) with $bindDN")
            LDAPCache.getBounded(bindDN, bindPwd)
            log.info("Bind cache updated for ${jaasContext.username}")
        }
        catch (e: LDAPException) {
            log.error("Authorization will fail! " +
                    "Exception when bind to (${config.host},${config.port}) - ${e.diagnosticMessage}")
        }
    }

    override fun isUserMemberOfAny(user: String, groups: List<String>, uuid: String): Boolean {

        var isMember: Boolean
        val userDN = toUserDN(user)
        val userDNBasta = toUserDNBasta(user)

        // check if group-user has at least one cache hit
        // user can be in ServiceAccounts xor ApplAccounts (BASTA created user)
        isMember =  groups
                .map { LDAPCache.alreadyGrouped(it, userDN) }
                .indexOfFirst { it == true }
                .let {
                    val found = (it >= 0)
                    if (found) log.info("[${groups[it]},$user] is cached ($uuid)")
                    found
                } || groups
                .map { LDAPCache.alreadyGrouped(it, userDNBasta) }
                .indexOfFirst { it == true }
                .let {
                    val found = (it >= 0)
                    if (found) log.info("[${groups[it]},$user] is cached ($uuid)")
                    found
                }

        if (isMember) return true

        // verify connection before LDAP operations
        val connOk = if (!ldapConnection.isConnected) {
            log.warn("Has lost connection to LDAP due to ${ldapConnection.disconnectMessage} - try reconnect ($uuid)")
            try {
                ldapConnection.reconnect()
                true
            }
            catch (e: LDAPException) {
                log.error("Authorization will fail - exception while trying reconnect - ${e.message} ($uuid)")
                false
            }
        }
        else true

        if (!connOk) return false

        // no cache hit, LDAP lookup for group membership
        // user can be in ServiceAccounts xor ApplAccounts (BASTA created user)
        groups.forEach {

            val groupDN = getGroupDN(it)
            val groupName = it

            log.info("Trying compare-matched for $groupDN - ${config.grpAttrName} - $userDN ($uuid)")
            isMember = isMember || try {
                (ldapConnection
                        .compare(CompareRequest(groupDN, config.grpAttrName, userDN))
                        .compareMatched()
                        .let {
                            if (it) {
                                LDAPCache.getGrouped(groupName, userDN)
                                log.info("Group cache updated for [$groupName,$user] ($uuid)")
                            }
                            it
                        }) || (ldapConnection
                                .compare(CompareRequest(groupDN, config.grpAttrName, userDNBasta))
                                .compareMatched()
                                .let {
                                    if (it) {
                                        LDAPCache.getGrouped(groupName, userDNBasta)
                                        log.info("Group cache updated for [$groupName,$user] ($uuid)")
                                    }
                                    it
                                })
            }
            catch(e: LDAPException) {
                log.error("Compare-matched exception - invalid group!, ${e.exceptionMessage} ($uuid)")
                false
            }
        }

        return isMember
    }

    private fun getGroupDN(group: String): String {

        val filter = Filter.createEqualityFilter(config.grpUid, group)

        return try{
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
            log.error("Cannot find $group under ${config.grpBaseDN}")
            ""
        }
    }

    companion object {

        private val log: Logger = LoggerFactory.getLogger(LDAPAuthorization::class.java)

        fun init(configFile: String = ""): LDAPAuthorization = when(configFile.isEmpty()) {
            true -> LDAPAuthorization(LDAPConfig.getByClasspath())
            else -> LDAPAuthorization(LDAPConfig.getBySource(configFile))
        }
    }
}