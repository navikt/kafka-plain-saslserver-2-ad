package no.nav.common.security

/**
 * Monitoring reflects utilization of log messages in kibana, in visualize components
 * and dashboard. All visualize components and dashboard are found by searching for 'kafka'
 *
 * Thus, change of text in Monitoring require corresponding change in kibana
 */

enum class Monitoring(val txt: String) {

    LDAP_BASE_TIME("LDAP connection time"),
    LDAP_BASE_FAILURE("Authentication and authorization will fail! Exception when connecting to"),

    AUTHENTICATION_CACHE_UPDATED("Bind cache updated"),
    AUTHENTICATION_CACHE_UPDATE_FAILED("Exception in userAdd"),
    AUTHENTICATION_LDAP_FAILURE("No LDAP connection, cannot authenticate"),
    AUTHENTICATION_FAILED("Authentication End - authentication failed"),
    AUTHENTICATION_SUCCESS("Authentication End - successful authentication"),

    AUTHORIZATION_CACHE_UPDATED("Group cache updated"),
    AUTHORIZATION_CACHE_UPDATE_FAILED("Exception in groupAndUserAdd"),
    AUTHORIZATION_LDAP_FAILURE("No LDAP connection, cannot verify"),
    AUTHORIZATION_BIND_FAILED("Authorization will fail! Exception during bind of"),
    AUTHORIZATION_BIND_TIME("LDAP bind time"),
    AUTHORIZATION_SEARCH_MISS("LDAP search couldn't resolve group DN for"),
    AUTHORIZATION_SEARCH_FAILURE("Cannot resolve group DN for"),
    AUTHORIZATION_GROUP_FAILURE("Cannot get group members"),
    AUTHORIZATION_FAILED("Authorization End")
}