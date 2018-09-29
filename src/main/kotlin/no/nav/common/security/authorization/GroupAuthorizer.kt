package no.nav.common.security.authorization

import kafka.security.auth.Acl
import no.nav.common.security.ldap.LDAPConfig
import no.nav.common.security.ldap.LDAPCache
import no.nav.common.security.ldap.LDAPAuthorization
import no.nav.common.security.ldap.toUserDNBasta
import no.nav.common.security.ldap.toUserDN
import org.apache.kafka.common.security.auth.KafkaPrincipal
import org.slf4j.LoggerFactory

/**
 * A class existing due to test capabilities
 * Instance of Kafka SimpleAuthorizer require logging to different server logs
 */

class GroupAuthorizer(private val uuid: String) : AutoCloseable {

    private fun userGroupMembershipIsCached(groups: List<String>, user: String): Boolean {

        val ldapConfig = LDAPConfig.getByClasspath()

        val userDN = ldapConfig.toUserDN(user)
        val userDNBasta = ldapConfig.toUserDNBasta(user)

        return groups.fold(false) { res, groupName ->
            res || (LDAPCache.groupAndUserExists(groupName, userDN) || LDAPCache.groupAndUserExists(groupName, userDNBasta))
                    .also { if (it) log.debug("[$groupName,$user] is cached ($uuid)") }
        }
    }

    private fun userGroupMembershipInLDAP(groups: List<String>, user: String): Boolean {

        val memberships = LDAPAuthorization.init(uuid).use { ldap -> ldap.isUserMemberOfAny(user, groups) }

        memberships.forEach {
            LDAPCache.groupAndUserAdd(it.groupName, it.userDN)
            log.info("Group cache updated for [${it.groupName},${it.userDN}] ($uuid)")
        }

        return memberships.isNotEmpty()
    }

    fun authorize(principal: KafkaPrincipal, acls: Set<Acl>): Boolean {

        val groups = acls.map { it.principal().name }
        val user = principal.name

        return when (userGroupMembershipIsCached(groups, user)) {
            true -> true
            else -> userGroupMembershipInLDAP(groups, user)
        }
    }

    override fun close() {
        // no need for cleanup
    }

    companion object {
        private val log = LoggerFactory.getLogger(GroupAuthorizer::class.java)
    }
}