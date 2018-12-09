package no.nav.common.security.authorization

import kafka.security.auth.Acl
import no.nav.common.security.ldap.LDAPCache
import no.nav.common.security.ldap.LDAPAuthorization
import org.apache.kafka.common.security.auth.KafkaPrincipal

/**
 * A class existing due to test capabilities
 * Instance of Kafka SimpleAuthorizer require logging to different server logs
 */

class GroupAuthorizer(private val uuid: String) : AutoCloseable {

    fun authorize(principal: KafkaPrincipal, acls: Set<Acl>): Boolean =
            acls
                    .map { it.principal().name.toLowerCase() }
                    .let { groups ->
                        val username = principal.name
                        // always check cache before ldap lookup
                        groups.any { groupName -> LDAPCache.groupAndUserExists(groupName, username, uuid) } ||
                                LDAPAuthorization.init(uuid)
                                        .use { ldap -> ldap.isUserMemberOfAny(username, groups) }
                                        .map { LDAPCache.groupAndUserAdd(it.groupName, it.user, uuid) }
                                        .isNotEmpty()
                    }

    override fun close() {}
}