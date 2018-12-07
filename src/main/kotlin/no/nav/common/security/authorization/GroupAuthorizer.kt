package no.nav.common.security.authorization

import kafka.security.auth.Acl
import no.nav.common.security.ldap.LDAPConfig
import no.nav.common.security.ldap.LDAPCache
import no.nav.common.security.ldap.LDAPAuthorization
import no.nav.common.security.ldap.toUserDNNodes
import org.apache.kafka.common.security.auth.KafkaPrincipal

/**
 * A class existing due to test capabilities
 * Instance of Kafka SimpleAuthorizer require logging to different server logs
 */

class GroupAuthorizer(private val uuid: String) : AutoCloseable {

    private fun userGroupMembershipIsCached(groups: List<String>, userDNs: List<String>): Boolean =
            userDNs.any { userDN -> groups.any { groupName -> LDAPCache.groupAndUserExists(groupName, userDN, uuid) } }

    private fun userGroupMembershipInLDAP(groups: List<String>, userDNs: List<String>): Boolean =
            LDAPAuthorization.init(uuid)
                    .use { ldap -> ldap.isUserMemberOfAny(userDNs, groups) }
                    .map { LDAPCache.groupAndUserAdd(it.groupName, it.userDN, uuid) }
                    .isNotEmpty()

    fun authorize(principal: KafkaPrincipal, acls: Set<Acl>): Boolean =
            LDAPConfig.getByClasspath().toUserDNNodes(principal.name).let { userDNs ->
                acls
                        .map { it.principal().name }
                        .let { groups ->
                            // always check cache before ldap lookup
                            userGroupMembershipIsCached(groups, userDNs) || userGroupMembershipInLDAP(groups, userDNs)
                        }
            }

    override fun close() {}
}