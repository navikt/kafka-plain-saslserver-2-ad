package no.nav.common.security.plain

import javax.security.auth.Subject
import javax.security.auth.callback.CallbackHandler
import javax.security.auth.login.LoginException
import javax.security.auth.spi.LoginModule

/**
 * A class from Kafka related to PlainSaslServer - no custom code here
 */

class PlainLoginModule : LoginModule {

    override fun initialize(
            subject: Subject,
            callbackHandler: CallbackHandler,
            sharedState: Map<String, *>,
            options: Map<String, *>) {

        // TTN change to more kotlin-like code
        subject.publicCredentials.add(options[USERNAME_CONFIG] as String)
        subject.privateCredentials.add(options[PASSWORD_CONFIG] as String)
    }

    @Throws(LoginException::class)
    override fun login(): Boolean {
        return true
    }

    @Throws(LoginException::class)
    override fun logout(): Boolean {
        return true
    }

    @Throws(LoginException::class)
    override fun commit(): Boolean {
        return true
    }

    @Throws(LoginException::class)
    override fun abort(): Boolean {
        return false
    }

    companion object {

        //TTN added const
        private const val USERNAME_CONFIG = "username"
        private const val PASSWORD_CONFIG = "password"

        init {
            PlainSaslServerProvider.initialize()
        }
    }
}