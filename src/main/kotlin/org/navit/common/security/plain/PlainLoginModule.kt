package org.navit.common.security.plain

import javax.security.auth.Subject
import javax.security.auth.callback.CallbackHandler
import javax.security.auth.login.LoginException
import javax.security.auth.spi.LoginModule

class PlainLoginModule : LoginModule {

    override fun initialize(subject: Subject, callbackHandler: CallbackHandler, sharedState: Map<String, *>, options: Map<String, *>) {
        val username = options[USERNAME_CONFIG] as String
        if (username != null)
            subject.publicCredentials.add(username)
        val password = options[PASSWORD_CONFIG] as String
        if (password != null)
            subject.privateCredentials.add(password)
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

        private val USERNAME_CONFIG = "username"
        private val PASSWORD_CONFIG = "password"

        init {
            PlainSaslServerProvider.initialize()
        }
    }
}