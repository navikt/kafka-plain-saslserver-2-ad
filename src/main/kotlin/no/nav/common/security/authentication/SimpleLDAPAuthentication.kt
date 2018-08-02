package no.nav.common.security.authentication

import no.nav.common.security.ldap.LDAPAuthentication
import no.nav.common.security.ldap.LDAPCache
import no.nav.common.security.ldap.LDAPConfig
import no.nav.common.security.ldap.toUserDN
import no.nav.common.security.ldap.toUserDNBasta
import org.apache.kafka.common.security.auth.AuthenticateCallbackHandler
import org.apache.kafka.common.security.plain.PlainAuthenticateCallback
import org.slf4j.LoggerFactory
import java.io.IOException
import javax.security.auth.callback.Callback
import javax.security.auth.callback.NameCallback
import javax.security.auth.callback.UnsupportedCallbackException
import javax.security.auth.login.AppConfigurationEntry

/**
 * A simple class for performing authentication
 * See KIP-86 for details
 * https://cwiki-test.apache.org/confluence/display/KAFKA/KIP-86%3A+Configurable+SASL+callback+handlers
 *
 * Also see a kind of framework
 * https://github.com/apache/kafka/blob/2.0/clients/src/main/java/org/apache/kafka/common/security/plain/internals/PlainServerCallbackHandler.java
 */
class SimpleLDAPAuthentication : AuthenticateCallbackHandler {

    private var jaasConfigEntries: MutableList<AppConfigurationEntry> = mutableListOf()

    @Throws(IOException::class, UnsupportedCallbackException::class)
    override fun handle(callbacks: Array<out Callback>?) {

        var username = ""

        callbacks?.forEach {

            when (it) {
                is NameCallback -> username = it.defaultName
                is PlainAuthenticateCallback -> it.authenticated(authenticate(username, it.password().toString()))
                else -> throw UnsupportedCallbackException(it)
            }
        }
    }

    private fun userInCache(username: String, password: String): Boolean =
            LDAPConfig.getByClasspath().let { ldapConfig ->
                LDAPCache.userExists(ldapConfig.toUserDN(username), password) ||
                        LDAPCache.userExists(ldapConfig.toUserDNBasta(username), password)
            }

    private fun authenticate(username: String, password: String): Boolean {

        log.debug("Authentication Start - $username")

        val authenticated = if (!userInCache(username, password))
            LDAPAuthentication.init()
                    .use { ldap ->
                        ldap.canUserAuthenticate(username, password)
                                .also { authenResult ->
                                    if (authenResult.authenticated) {
                                        LDAPCache.userAdd(authenResult.userDN, password)
                                        log.info("Bind cache updated for ${authenResult.userDN}")
                                    } else
                                        log.error("Cannot authenticate $username, please verify LDAP config")
                                }
                    }.authenticated
        else {
            log.debug("$username is cached")
            true
        }

        if (authenticated)
            log.debug("Authentication End - successful authentication of $username")
        else {
            log.error("Authentication End - authentication failed for $username")
        }

        return authenticated
    }

    override fun configure(
        configs: MutableMap<String, *>?,
        saslMechanism: String?,
        jaasConfigEntries: MutableList<AppConfigurationEntry>?
    ) {
        this.jaasConfigEntries = jaasConfigEntries ?: mutableListOf()
    }

    override fun close() {}

    companion object {
        private val log = LoggerFactory.getLogger(SimpleLDAPAuthentication::class.java)
    }
}