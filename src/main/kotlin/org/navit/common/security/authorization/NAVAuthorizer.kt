package org.navit.common.security.authorization

import kafka.security.auth.Acl
import org.apache.kafka.common.security.auth.KafkaPrincipal
import org.navit.common.security.authentication.LDAPProxy
import org.slf4j.LoggerFactory

class NAVAuthorizer {

    private val ldapProxy: LDAPProxy

    init {

        val configFile = ClassLoader.getSystemResource(LDAPProxy.configFile)?.path ?: ""

        if (configFile.isEmpty()) log.error("$navAuthorization authorization will fail, no ${LDAPProxy.configFile} found!")

        ldapProxy = LDAPProxy.init(configFile)
        log.info("$navAuthorization has initialized ldap proxy")
    }

    fun authorize(principal: KafkaPrincipal, acls: Set<Acl>): Boolean {

        acls.forEach { log.info("$navAuthorization ALLOW ACL: $it") }

        //getBinded allow principals, should be LDAP groups only
        val ldapGroups: List<String> = acls.map { it.principal().name  }

        val authorized = ldapProxy.isUserMemberOfAny(principal.name, ldapGroups)

        when(authorized) {
            true -> log.info("$navAuthorization $principal is authorized!")
            false -> log.info("$navAuthorization $principal is not authorized!")
        }

        return authorized
    }

    companion object {
        private val log = LoggerFactory.getLogger(NAVAuthorizer::class.java)
        private const val navAuthorization = "NAV authorization:"
    }
}