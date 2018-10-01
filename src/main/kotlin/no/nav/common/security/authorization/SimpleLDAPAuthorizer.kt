package no.nav.common.security.authorization

import kafka.network.RequestChannel
import kafka.security.auth.Acl
import kafka.security.auth.Operation
import kafka.security.auth.Resource
import kafka.security.auth.SimpleAclAuthorizer
import org.apache.kafka.common.acl.AclPermissionType
import org.apache.kafka.common.resource.ResourceType
import org.apache.kafka.common.security.auth.KafkaPrincipal
import org.slf4j.LoggerFactory

/**
 * A class adding LDAP group membership verification to Kafka SimpleAuthorizer
 * The overall prerequisite framework is the following
 * - Expecting LDAP groups in topic ACLS
 * - A principal is authorized through membership in group
 * - No group considerations, thus, empty ACL for group resource yield authorization
 * - No deny considerations, implicitly through non-membership
 *
 * See https://github.com/apache/kafka/tree/2.0/core/src/main/scala/kafka/security/auth
 */

class SimpleLDAPAuthorizer : SimpleAclAuthorizer() {

    override fun authorize(session: RequestChannel.Session?, operation: Operation?, resource: Resource?): Boolean {

        // nothing to do if already authorized
        // this includes the configurable default handling for non ACLs case - ' allow.everyone.if.no.acl.found'
        if (super.authorize(session, operation, resource)) return true

        val principal = session?.principal()
        val lOperation = operation?.toString()
        val host = session?.clientAddress()?.hostAddress
        val lResource = resource?.toString()

        val uuid = java.util.UUID.randomUUID().toString()
        val authContext = "$principal trying $lOperation from $host on $lResource ($uuid)"

        log.debug("Authorization Start -  $authContext")

        // TODO ResourceType.GROUP - under change in minor version - CAREFUL!
        // Warning! Assuming no group considerations, thus implicitly, always empty group access control lists
        if (resource?.resourceType()?.toJava() == ResourceType.GROUP) {
            log.debug("Authorization End - $authContext is authorized!")
            return true
        }

        // TODO AclPermissionType.ALLOW - under change in minor version - CAREFUL!
        // userAdd allow access control lists for resource and given operation
        val sacls = getAcls(resource)
                .filter { it.operation() == operation && it.permissionType().toJava() == AclPermissionType.ALLOW }

        // switch to kotlin set, making testing easier
        val acls = mutableSetOf<Acl>()
        sacls.foreach { acls += it }

        log.debug("$lOperation has following Allow ACLs for $lResource: ${acls.map { it.principal().name }} ($uuid)")

        // nothing to do if empty acl set
        if (acls.isEmpty()) {
            log.error("Authorization End - $authContext - empty ALLOW ACL for [$lResource,$lOperation], is not authorized ($uuid)")
            return false
        }

        // verify membership, either cached or through LDAP - see GroupAuthorizer
        val anonymous = KafkaPrincipal(KafkaPrincipal.USER_TYPE, "ANONYMOUS")
        val isAuthorized = GroupAuthorizer(uuid).use { it.authorize(session?.principal() ?: anonymous, acls) }

        when (isAuthorized) {
            true -> log.debug("Authorization End - $authContext is authorized!")
            false -> log.error("Authorization End - $authContext is not authorized!")
        }

        return isAuthorized
    }

    companion object {
        private val log = LoggerFactory.getLogger(SimpleLDAPAuthorizer::class.java)
    }
}