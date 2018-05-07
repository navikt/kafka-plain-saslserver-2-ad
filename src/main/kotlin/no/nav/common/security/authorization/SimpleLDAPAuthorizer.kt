package no.nav.common.security.authorization

import kafka.network.RequestChannel
import kafka.security.auth.*
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
 */

class SimpleLDAPAuthorizer : SimpleAclAuthorizer() {

    override fun authorize(session: RequestChannel.Session?, operation: Operation?, resource: Resource?): Boolean {

        // nothing to do if already authorized
        if (super.authorize(session, operation, resource)) return true

        val principal = session?.principal()
        val lOperation = operation?.toString()
        val host = session?.clientAddress()?.hostAddress
        val lResource = resource?.toString()

        val uuid = java.util.UUID.randomUUID().toString()

        log.debug("Authorization Start -  $principal trying $lOperation from $host on $lResource ($uuid)")

        //TODO ResourceType.GROUP - under change in minor version - CAREFUL!
        // Warning! Assuming no group considerations, thus implicitly, always empty group access control lists
        if (resource?.resourceType()?.toJava() == ResourceType.GROUP) {
            log.debug("Authorization End - $principal trying $lOperation from $host on $lResource is authorized ($uuid)")
            return true
        }

        //TODO AclPermissionType.ALLOW - under change in minor version - CAREFUL!
        // userAdd allow access control lists for resource and given operation
        val sacls = getAcls(resource)
                .filter { it.operation() == operation && it.permissionType().toJava() == AclPermissionType.ALLOW }

        // switch to kotlin set, making testing easier
        var acls: Set<Acl> = emptySet()
        sacls.foreach { acls += it }

        // nothing to do if empty acl set
        if (acls.isEmpty()) {
            log.debug("Authorization End - empty ALLOW ACL for [$lResource,$lOperation], is not authorized ($uuid)")
            return false
        }

        return GroupAuthorizer().use { navAuthorizer ->
            navAuthorizer.authorize(
                    session?.principal() ?: KafkaPrincipal(KafkaPrincipal.USER_TYPE,"ANONYMOUS"),
                    acls,
                    uuid
            ).let { isAuthorized ->
                when(isAuthorized) {
                    true -> log.debug("Authorization End - $principal is authorized! ($uuid)")
                    false -> log.debug("Authorization End - $principal is not authorized! ($uuid)")
                }
                isAuthorized
            }
        }
    }

    companion object {
        private val log = LoggerFactory.getLogger(SimpleLDAPAuthorizer::class.java)
    }
}