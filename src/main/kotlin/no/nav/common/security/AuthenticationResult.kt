package no.nav.common.security

sealed class AuthenticationResult {
    object NoLDAPConnection : AuthenticationResult()
    object SuccessfulBind : AuthenticationResult()
    data class UnsuccessfulBind(val error: String) : AuthenticationResult()
}