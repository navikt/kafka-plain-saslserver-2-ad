package org.navit.common.security.authorization

import kafka.network.RequestChannel
import kafka.security.auth.Operation
import kafka.security.auth.Resource
import kafka.security.auth.SimpleAclAuthorizer
import org.slf4j.LoggerFactory

class LDAPAuthorizer : SimpleAclAuthorizer() {

    override fun authorize(session: RequestChannel.Session?, operation: Operation?, resource: Resource?): Boolean {

        val authorized = super.authorize(session, operation, resource)

        val principal = session?.principal()
        val host = session?.clientAddress()?.hostAddress
        val op = operation?.toString()
        val res = resource?.name()
        val resType = resource?.resourceType()?.toString()

        log.info("Principal $principal trying operation($op) from host($host) on resource($res/$resType) ($authorized)")

        return true
    }

    companion object {
        private val log = LoggerFactory.getLogger(LDAPAuthorizer::class.java)
    }
}