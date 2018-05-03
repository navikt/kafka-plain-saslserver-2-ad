package no.nav.common.security.authorization

import kafka.security.auth.Acl
import no.nav.common.security.ldap.*
import org.apache.kafka.common.security.auth.KafkaPrincipal
import org.slf4j.LoggerFactory

/**
 * A class existing due to test capabilities
 * Instance of Kafka SimpleAuthorizer require logging to different server logs
 */

class GroupAuthorizer : AutoCloseable {

    fun authorize(principal: KafkaPrincipal, acls: Set<Acl>, uuid: String): Boolean =

            acls.map {
                log.debug("ALLOW ACL: $it ($uuid)")
                it.principal().name
            }.let { groups ->

                val ldapConfig = LDAPConfig.getByClasspath()

                val userDN = ldapConfig.toUserDN(principal.name)
                val userDNBasta = ldapConfig.toUserDNBasta(principal.name)

                val isCached =  groups
                        .map { LDAPCache.alreadyGrouped(it, userDN) || LDAPCache.alreadyGrouped(it, userDNBasta) }
                        .indexOfFirst { it == true }
                        .let {
                            val found = (it >= 0)
                            if (found) log.debug("[${groups[it]},${principal.name}] is cached ($uuid)")
                            found
                        }

                if (isCached)
                    true
                else
                    LDAPAuthorization.init().use { ldap -> ldap.isUserMemberOfAny(principal.name, groups, uuid) }
            }

    override fun close() {
        //no need for cleanup
    }

    companion object {
        private val log = LoggerFactory.getLogger(GroupAuthorizer::class.java)
    }
}