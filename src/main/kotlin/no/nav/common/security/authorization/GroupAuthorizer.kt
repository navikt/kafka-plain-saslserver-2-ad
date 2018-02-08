package no.nav.common.security.authorization

import kafka.security.auth.Acl
import org.apache.kafka.common.security.auth.KafkaPrincipal
import no.nav.common.security.ldap.LDAPAuthorization
import no.nav.common.security.ldap.LDAPBase
import org.slf4j.LoggerFactory

/**
 * A class existing due to test capabilities
 * Instance of Kafka SimpleAuthorizer require logging to different server logs
 */

class GroupAuthorizer {

    private val ldap = LDAPAuthorization.init()

    fun authorize(principal: KafkaPrincipal, acls: Set<Acl>): Boolean {

        acls.forEach { log.info("ALLOW ACL: $it") }

        // get allow principals, should be LDAP groups only
        val ldapGroups: List<String> = acls.map { it.principal().name  }

        return ldap.isUserMemberOfAny(principal.name, ldapGroups)
    }

    companion object {
        private val log = LoggerFactory.getLogger(GroupAuthorizer::class.java)
    }
}