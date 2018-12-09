package no.nav.common.security.authentication

import no.nav.common.security.Monitoring
import no.nav.common.security.ldap.LDAPAuthentication
import no.nav.common.security.ldap.LDAPCache
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
 * https://cwiki.apache.org/confluence/display/KAFKA/KIP-86%3A+Configurable+SASL+callback+handlers
 *
 * Also see a kind of framework
 * https://github.com/apache/kafka/blob/2.0/clients/src/main/java/org/apache/kafka/common/security/plain/internals/PlainServerCallbackHandler.java
 */
class SimpleLDAPAuthentication : AuthenticateCallbackHandler {

    init {
        log.debug("${SimpleLDAPAuthentication::class.java.canonicalName} object created")
    }

    private var jaasConfigEntries: MutableList<AppConfigurationEntry> = mutableListOf()

    private inline fun <reified T> Array<out Callback>.getFirst(): T? = this.firstOrNull { it is T } as T

    private inline fun <reified T, reified U> Array<out Callback>.other(): Callback? =
            this.firstOrNull { it !is T && it !is U }

    @Throws(IOException::class, UnsupportedCallbackException::class)
    override fun handle(callbacks: Array<out Callback>?) {

        callbacks?.getFirst<PlainAuthenticateCallback>()?.let { plainCB ->
            plainCB.authenticated(
                    authenticate(
                            callbacks.getFirst<NameCallback>()?.defaultName ?: "",
                            plainCB.password().joinToString("")
                    )
            )
        }

        callbacks?.other<NameCallback, PlainAuthenticateCallback>()?.let { throw UnsupportedCallbackException(it) }
    }

    private fun authenticate(username: String, password: String): Boolean =
            // always check cache before ldap lookup
            (
                    LDAPCache.userExists(username, password) ||
                    LDAPAuthentication.init()
                            .use { ldap -> ldap.canUserAuthenticate(username, password) }
                            .also { if (it) LDAPCache.userAdd(username, password) }
                    )
                    .also { isAuthenticated ->
                        log.debug("Authentication Start - $username")
                        if (isAuthenticated) log.info("${Monitoring.AUTHENTICATION_SUCCESS.txt} of $username")
                        else log.error("${Monitoring.AUTHENTICATION_FAILED.txt} for $username")
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