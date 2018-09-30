package no.nav.common.security.authorization

import kafka.security.auth.Acl
import no.nav.common.security.ldap.LDAPConfig
import no.nav.common.security.ldap.LDAPCache
import no.nav.common.security.ldap.LDAPAuthorization
import no.nav.common.security.ldap.toUserDNNodes
import org.apache.kafka.common.security.auth.KafkaPrincipal
import org.slf4j.LoggerFactory

/**
 * A class existing due to test capabilities
 * Instance of Kafka SimpleAuthorizer require logging to different server logs
 */

class GroupAuthorizer(private val uuid: String) : AutoCloseable {

    private fun userGroupMembershipIsCached(groups: List<String>, user: String): Boolean =
        LDAPConfig.getByClasspath().let { ldapConfig ->
            val userNodes = ldapConfig.toUserDNNodes(user)

            groups.fold(false) { res, groupName ->
                res || userNodes.fold(false) { exists, uDN -> exists || LDAPCache.groupAndUserExists(groupName, uDN) }
                        .also { if (it) log.debug("[$groupName,$user] is cached ($uuid)") }
            }
        }

    private fun userGroupMembershipInLDAP(groups: List<String>, user: String): Boolean =
        LDAPAuthorization.init(uuid).use { ldap -> ldap.isUserMemberOfAny(user, groups) }
                .map {
                    log.info("Group cache updated for [${it.groupName},${it.userDN}] ($uuid)")
                    LDAPCache.groupAndUserAdd(it.groupName, it.userDN)
                }
                .isNotEmpty()

    fun authorize(principal: KafkaPrincipal, acls: Set<Acl>): Boolean =
        acls.map { it.principal().name }.let { groups ->
                when (userGroupMembershipIsCached(groups, principal.name)) {
                    true -> true
                    else -> userGroupMembershipInLDAP(groups, principal.name)
                }
        }

    override fun close() {
        // no need for cleanup
    }

    companion object {
        private val log = LoggerFactory.getLogger(GroupAuthorizer::class.java)
    }
}