package no.nav.common.security.ldap

import com.unboundid.ldap.sdk.CompareRequest
import com.unboundid.ldap.sdk.LDAPException
import org.slf4j.Logger
import org.slf4j.LoggerFactory

/**
 * A class verifying group membership with LDAP compare-matched
 */

class LDAPAuthorization private constructor(val config: ADConfig.Config) : LDAPBase(config) {

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
    private fun toGroupDN(group: String) =  "${config.grpUid}=$group,${config.grpBaseDN}"

    // In authorization context, needs to bind the connection before compare-match between group and user
    // due to no anonymous access allowed for LDAP operations like search, compare, ...
    private val bindDN = toUserDN(jaasContext.username)
    private val bindPwd = jaasContext.password

    init {
        log.info("Binding information for authorization fetched from JAAS config file [$bindDN]")

        try {
            ldapConnection.bind(bindDN,bindPwd)
            log.info("Successfully bind to (${config.host},${config.port}) with $bindDN")
        }
        catch (e: LDAPException) {
            log.error("Authorization will fail! " +
                    "Exception when bind to (${config.host},${config.port}) - ${e.diagnosticMessage}")
        }
    }

    override fun isUserMemberOfAny(user: String, groups: List<String>): Boolean {

        var isMember: Boolean
        val userDN = toUserDN(user)

        // check if group-user has at least one cache hit
        isMember =  groups
                .map { LDAPCache.alreadyGrouped(toGroupDN(it), userDN) }
                .indexOfFirst { it == true }
                .let {
                    val found = (it >= 0)
                    if (found) log.info("[${groups[it]},$user] is cached")
                    found
                }

        if (isMember) return true

        // no cache hit, LDAP lookup for group membership
        groups.forEach {

            val groupDN = toGroupDN(it)
            val groupName = it

            log.info("Trying compare-matched for $groupDN - ${config.grpAttrName} - $userDN")
            isMember = isMember || try {
                ldapConnection
                        .compare(CompareRequest(groupDN, config.grpAttrName, userDN))
                        .compareMatched()
                        .let {
                            if (it) {
                                LDAPCache.getGrouped(groupDN, userDN)
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

        fun init(configFile: String = ""): LDAPAuthorization = when(configFile.isEmpty()) {
            true -> LDAPAuthorization(ADConfig.getByClasspath())
            else -> LDAPAuthorization(ADConfig.getBySource(configFile))
        }
    }
}