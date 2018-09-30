package no.nav.common.security.authentication

import no.nav.common.security.ldap.LDAPAuthentication
import no.nav.common.security.ldap.LDAPCache
import no.nav.common.security.ldap.LDAPConfig
import no.nav.common.security.ldap.toUserDNNodes
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

    private fun userInCache(username: String, password: String): Boolean =
            LDAPConfig.getByClasspath().let { ldapConfig ->
                ldapConfig.toUserDNNodes(username).fold(false) { exists, uDN ->
                    exists || LDAPCache.userExists(uDN, password) }.also { if (it) log.debug("$username is cached") }
            }

    private fun userBoundedInLDAP(username: String, password: String): Boolean =
            LDAPAuthentication.init()
                    .use { ldap ->
                        ldap.canUserAuthenticate(username, password)
                                .also { authenResult ->
                                    if (authenResult.authenticated) {
                                        LDAPCache.userAdd(authenResult.userDN, password)
                                        log.info("Bind cache updated for ${authenResult.userDN}")
                                    } // no else since all scenarios are covered in LDAPAuthentication
                                }
                    }.authenticated

    private fun authenticate(username: String, password: String): Boolean =
        "Authentication Start - $username".let { logTxt ->
            log.debug(logTxt)
            when (userInCache(username, password)) {
                true -> true
                else -> userBoundedInLDAP(username, password)
            }.also {
                if (it)
                    log.info("Authentication End - successful authentication of $username")
                else
                    log.error("Authentication End - authentication failed for $username")
            }
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