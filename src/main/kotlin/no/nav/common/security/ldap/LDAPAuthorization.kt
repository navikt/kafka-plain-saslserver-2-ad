package no.nav.common.security.ldap

import com.unboundid.ldap.sdk.DN
import com.unboundid.ldap.sdk.LDAPException
import com.unboundid.ldap.sdk.Filter
import com.unboundid.ldap.sdk.SearchRequest
import com.unboundid.ldap.sdk.SearchScope
import com.unboundid.ldap.sdk.LDAPSearchException
import no.nav.common.security.AuthenticationResult
import no.nav.common.security.Monitoring
import org.slf4j.Logger
import org.slf4j.LoggerFactory

/**
 * A class verifying group membership with LDAP
 */

class LDAPAuthorization(
    private val uuid: String,
    val config: LDAPConfig.Config = LDAPConfig.getByClasspath()
) : LDAPBase(config) {

    // In authorization context, needs to bind the connection before compare-match between group and user
    // due to no anonymous access allowed for LDAP operations like search, compare, ...
    private val connectionAndBindIsOk = when {
        JAASContext.username.isEmpty() || JAASContext.password.isEmpty() -> false
        !ldapConnection.isConnected -> false
        else -> authenticationOk(JAASContext.username, JAASContext.password).let { authenticationResult ->
            when (authenticationResult) {
                is AuthenticationResult.SuccessfulBind -> true
                        .also { log.debug("Successfully bind to (${config.host},${config.port}) with ${JAASContext.username}") }
                is AuthenticationResult.NoLDAPConnection -> false
                        .also { log.error("${Monitoring.AUTHORIZATION_BIND_FAILED.txt} ${JAASContext.username} to " +
                                "(${config.host},${config.port})") }
                is AuthenticationResult.UnsuccessfulBind -> false
                        .also { log.error("${Monitoring.AUTHORIZATION_BIND_FAILED.txt} ${JAASContext.username} to " +
                                "(${config.host},${config.port})") }
            }
        }
    }

    private fun getGroupDN(groupName: String): String =
            try {
                val filter = Filter.createEqualityFilter(config.grpUid, groupName)

                ldapConnection
                        .search(SearchRequest(config.grpBaseDN, SearchScope.SUB, filter, SearchRequest.NO_ATTRIBUTES))
                        .let {
                            if (it.entryCount == 1)
                                it.searchEntries[0].dn
                            else {
                                log.error("${Monitoring.AUTHORIZATION_SEARCH_MISS.txt} $groupName under ${config.grpBaseDN} ($uuid)")
                                ""
                            }
                        }
            } catch (e: LDAPSearchException) {
                log.error("${Monitoring.AUTHORIZATION_SEARCH_FAILURE.txt} $groupName under ${config.grpBaseDN} ($uuid)")
                ""
            }

    private fun getGroupMembers(groupDN: String): List<String> =
            try {
                if (groupDN.isNotEmpty())
                    ldapConnection.getEntry(groupDN)
                            ?.getAttributeValues(config.grpAttrName)
                            ?.map { DN(it).rdn.attributeValues.first().toLowerCase() } ?: emptyList()
                else
                    emptyList()
            } catch (e: LDAPException) {
                log.error("${Monitoring.AUTHORIZATION_GROUP_FAILURE.txt} - ${config.grpAttrName} - for $groupDN ($uuid)")
                emptyList()
            }

    data class AuthorResult(val groupName: String, val user: String)

    fun isUserMemberOfAny(username: String, groups: List<String>): Set<AuthorResult> =
            if (!connectionAndBindIsOk)
                emptySet<AuthorResult>()
                        .also { log.error("${Monitoring.AUTHORIZATION_LDAP_FAILURE.txt} $username membership in $groups ($uuid)") }
            else
                groups.flatMap { groupName ->
                    getGroupMembers(getGroupDN(groupName)).let { members ->
                        log.debug("Group membership, intersection of $members and $username ($uuid)")
                        members.intersect(listOf(username)).map { usr -> AuthorResult(groupName, usr) }
                    }
                }
                        .also { result -> log.debug("Intersection result - $result ($uuid)") }
                        .toSet()

    companion object {

        private val log: Logger = LoggerFactory.getLogger(LDAPAuthorization::class.java)
    }
}