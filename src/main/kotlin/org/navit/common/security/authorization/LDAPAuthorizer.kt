package org.navit.common.security.authorization

import kafka.network.RequestChannel
import kafka.security.auth.*
import org.apache.kafka.common.acl.AclPermissionType
import org.apache.kafka.common.resource.ResourceType
import org.navit.common.security.authentication.LDAPProxy
import org.slf4j.LoggerFactory

class LDAPAuthorizer : SimpleAclAuthorizer() {

    private val ldapProxy: LDAPProxy

    init {

        val configFile = ClassLoader.getSystemResource("adconfig.yaml")?.path ?: ""

        if (configFile.isEmpty()) log.error("Authorization will fail, no adconfig.yaml found!")

        ldapProxy = LDAPProxy.init(configFile)
    }

    override fun authorize(session: RequestChannel.Session?, operation: Operation?, resource: Resource?): Boolean {

        val authorized = super.authorize(session, operation, resource)

        // nothing to do if already authorized
        if (authorized) return true

        log.info("Principal ${session?.principal()} trying operation(${operation?.toString()}) " +
                "from host(${session?.clientAddress()?.hostAddress}) " +
                "on resource(${resource?.toString()}) ($authorized)")

        // Warning! Assuming no group considerations, thus implicitly always empty group acls
        if (resource?.resourceType()?.toJava() == ResourceType.GROUP) {
            log.info("Warning - no group considerations - principal ${session?.principal()} " +
                    "trying operation(${operation?.toString()}) on resource($resource) is ALLOWED!")
            return true
        }

        // get allow acls for current operation, also hurry inside the kotlin turf
        val sacls = getAcls(resource).filter { it.operation() == operation && it.permissionType().toJava() == AclPermissionType.ALLOW }
        var acls: Set<Acl> = emptySet()

        sacls.foreach { acls += it }

        // nothing to do if empty acl set
        if (acls.isEmpty()) {
            log.info("Allow ACLs empty for resource ${resource?.name()}, operation ${operation?.toString()} - NOT ALLOWED")
            return false
        }

        acls.forEach { log.info("acl - $it") }

        // get allow principals, remove the prefix - <User>:<name>
        val aprin = acls.map { it.principal().toString().substringAfter(":") }

        aprin.forEach { log.info("principals - $it") }

        return ldapProxy.isUserMemberOfAny(session?.principal().toString().substringAfter(":"),aprin)
    }

    companion object {
        private val log = LoggerFactory.getLogger(LDAPAuthorizer::class.java)
    }
}