package org.navit.common.security.authorizer

import kafka.network.RequestChannel
import kafka.security.auth.Operation
import kafka.security.auth.Resource
import kafka.security.auth.SimpleAclAuthorizer
import org.slf4j.LoggerFactory

class LDAPAuthorizer : SimpleAclAuthorizer() {

    override fun authorize(session: RequestChannel.Session?, operation: Operation?, resource: Resource?): Boolean {
        val authorized = super.authorize(session, operation, resource)

        return authorized
    }

    companion object {
        private val log = LoggerFactory.getLogger(LDAPAuthorizer::class.java)
    }
}