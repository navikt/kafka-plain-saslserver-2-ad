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

class GroupAuthorizer : AutoCloseable {

    fun authorize(principal: KafkaPrincipal, acls: Set<Acl>, uuid: String): Boolean =

            acls.map { it.principal().name }.let { groups ->

                val ldapConfig = LDAPConfig.getByClasspath()

                val userDN = ldapConfig.toUserDN(principal.name)
                val userDNBasta = ldapConfig.toUserDNBasta(principal.name)

                val cachedUserInGroups = groups
                        .map { groupName ->
                            if (
                                    LDAPCache.groupAndUserExists(groupName, userDN) ||
                                    LDAPCache.groupAndUserExists(groupName, userDNBasta)
                            )
                                Pair(true, groupName)
                            else
                                Pair(false, groupName)
                        }
                        .filter { pair -> pair.first }

                if (cachedUserInGroups.isNotEmpty()) {
                    log.debug("[${cachedUserInGroups.map { it.second }},${principal.name}] is cached ($uuid)")
                    true
                } else
                    LDAPAuthorization.init()
                            .use { ldap -> ldap.isUserMemberOfAny(principal.name, groups, uuid) }
                            .let { uInGSet ->
                                uInGSet.forEach {
                                    LDAPCache.groupAndUserAdd(it.groupName, it.userDN)
                                    log.info("Group cache updated for [${it.groupName},${it.userDN}] ($uuid)")
                                }
                                uInGSet.isNotEmpty()
                            }
            }

    override fun close() {
        // no need for cleanup
    }

    companion object {
        private val log = LoggerFactory.getLogger(GroupAuthorizer::class.java)
    }
}