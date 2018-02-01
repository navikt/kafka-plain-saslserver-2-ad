package org.navit.common.security.authorization

import kafka.network.RequestChannel
import kafka.security.auth.Operation
import kafka.security.auth.Resource
import kafka.security.auth.SimpleAclAuthorizer
import org.slf4j.LoggerFactory

class LDAPAuthorizer : SimpleAclAuthorizer() {

    override fun authorize(session: RequestChannel.Session?, operation: Operation?, resource: Resource?): Boolean {

        val authorized = super.authorize(session, operation, resource)

        if (!authorized) {
            log.info("Principal ${session?.principal()} trying operation(${operation?.toString()}) " +
                    "from host(${session?.clientAddress()?.hostAddress}) " +
                    "on resource(${resource?.toString()}) ($authorized)")

            val acls = super.getAcls(resource)

            if (acls.size() == 0)
                log.info("ACLs for resource ${resource?.name()} is empty")
            else
                acls.foreach { log.info("acl - $it") }
        }

        return authorized
    }

    companion object {
        private val log = LoggerFactory.getLogger(LDAPAuthorizer::class.java)
    }
}