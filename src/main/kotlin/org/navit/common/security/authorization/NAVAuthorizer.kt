package org.navit.common.security.authorization

import kafka.security.auth.Acl
import org.apache.kafka.common.security.auth.KafkaPrincipal
import org.navit.common.security.authentication.LDAPProxy
import org.slf4j.LoggerFactory

class NAVAuthorizer {

    private val ldapProxy: LDAPProxy

    init {

        val configFile = ClassLoader.getSystemResource(LDAPProxy.CONFIGFILE)?.path ?: ""

        if (configFile.isEmpty()) log.error("authorization will fail, no ${LDAPProxy.CONFIGFILE} found!")

        ldapProxy = LDAPProxy.init(configFile)
    }

    fun authorize(principal: KafkaPrincipal, acls: Set<Acl>): Boolean {

        acls.forEach { log.info("ALLOW ACL: $it") }

        //getBounded allow principals, should be LDAP groups only
        val ldapGroups: List<String> = acls.map { it.principal().name  }

        return ldapProxy.isUserMemberOfAny(principal.name, ldapGroups)
    }

    companion object {
        private val log = LoggerFactory.getLogger(NAVAuthorizer::class.java)
    }
}