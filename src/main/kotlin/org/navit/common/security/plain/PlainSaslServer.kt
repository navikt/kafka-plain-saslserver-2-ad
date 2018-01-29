package org.navit.common.security.plain

import com.unboundid.ldap.sdk.ResultCode
import org.navit.common.security.activedirectory.LDAPProxy
import javax.security.sasl.Sasl
import javax.security.sasl.SaslException
import javax.security.auth.callback.CallbackHandler
import javax.security.sasl.SaslServer
import javax.security.sasl.SaslServerFactory

import java.util.Arrays
import java.io.UnsupportedEncodingException

import org.apache.kafka.common.errors.SaslAuthenticationException
//TTN import org.apache.kafka.common.security.JaasContext
//TTN import org.apache.kafka.common.security.authenticator.SaslServerCallbackHandler


class PlainSaslServer/*TTN (val jaasContext: JaasContext)*/ : SaslServer {

    private var complete: Boolean = false
    private var authorizationId: String = ""

    @Throws(SaslException::class, SaslAuthenticationException::class)
    override fun evaluateResponse(response: ByteArray): ByteArray {
        /*
         * Message format (from https://tools.ietf.org/html/rfc4616):
         *
         * message   = [authzid] UTF8NUL authcid UTF8NUL passwd
         * authcid   = 1*SAFE ; MUST accept up to 255 octets
         * authzid   = 1*SAFE ; MUST accept up to 255 octets
         * passwd    = 1*SAFE ; MUST accept up to 255 octets
         * UTF8NUL   = %x00 ; UTF-8 encoded NUL character
         *
         * SAFE      = UTF1 / UTF2 / UTF3 / UTF4
         *                ;; any UTF-8 encoded Unicode character except NUL
         */

        val tokens: Array<String>
        try {
            tokens = String(response, Charsets.UTF_8).split("\u0000".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
        } catch (e: UnsupportedEncodingException) {
            throw SaslAuthenticationException("UTF-8 encoding not supported", e)
        }

        if (tokens.size != 3)
            throw SaslAuthenticationException("Invalid SASL/PLAIN response: expected 3 tokens, got " + tokens.size)
        val authorizationIdFromClient = tokens[0]
        val username = tokens[1]
        val password = tokens[2]

        if (username.isEmpty()) {
            throw SaslAuthenticationException("Authentication failed: username not specified")
        }
        if (password.isEmpty()) {
            throw SaslAuthenticationException("Authentication failed: password not specified")
        }


        /* TTN
        val expectedPassword = jaasContext.configEntryOption(JAAS_USER_PREFIX + username,
                PlainLoginModule::class.java.name)
        if (password != expectedPassword) {
            throw SaslAuthenticationException("Authentication failed: Invalid username or password")
        }
        */

        //TTN
        //TODO Brutal establishment of LDAP connection and closing just after - where to place LDAP proxy for longer living?

        // need to have the directory containing the adconfig.yaml as part of the classpath
        val configFile = ClassLoader.getSystemResource("adconfig.yaml")?.path ?: ""

        if (configFile.isEmpty()) throw SaslAuthenticationException("Authentication will fail, no adconfig.yaml found!")

        val ldap = LDAPProxy.init(configFile)
        val resultID = ldap.verifyUserAndPassword(username, password)

        when (resultID) {
            ResultCode.CONNECT_ERROR -> throw SaslAuthenticationException("Authentication failed: Cannot reach LDAP (${ldap.host}/${ldap.port})")
            ResultCode.NO_SUCH_OBJECT -> throw SaslAuthenticationException("Authentication failed: Invalid baseDN (${ldap.baseDN}) as start point")
            ResultCode.FILTER_ERROR -> throw SaslAuthenticationException("Authentication failed: Invalid filter (${ldap.filter}) in YAML config")
            ResultCode.INAPPROPRIATE_MATCHING -> throw SaslAuthenticationException("Authentication failed: check baseDN (${ldap.baseDN}) and filter (${ldap.filter}) in YAML config")
            ResultCode.INVALID_CREDENTIALS -> throw SaslAuthenticationException("Authentication failed: Invalid username($username) or password")
            ResultCode.SUCCESS -> {}
            else -> throw SaslException("Authentication failed: Unknown exception")
        }
        //NTT

        if (!authorizationIdFromClient.isEmpty() && authorizationIdFromClient != username)
            throw SaslException("Authentication failed: Client requested an authorization id that is different from username")

        this.authorizationId = username

        complete = true
        return ByteArray(0)
    }

    @Throws(IllegalStateException::class)
    override fun getAuthorizationID(): String? {
        if (!complete)
            throw IllegalStateException("Authentication exchange has not completed")
        return authorizationId
    }

    override fun getMechanismName(): String {
        return PLAIN_MECHANISM
    }

    @Throws(IllegalStateException::class)
    override fun getNegotiatedProperty(propName: String): Any? {
        if (!complete)
            throw IllegalStateException("Authentication exchange has not completed")
        return null
    }

    override fun isComplete(): Boolean {
        return complete
    }

    @Throws(IllegalStateException::class)
    override fun unwrap(incoming: ByteArray, offset: Int, len: Int): ByteArray {
        if (!complete)
            throw IllegalStateException("Authentication exchange has not completed")
        return Arrays.copyOfRange(incoming, offset, offset + len)
    }

    @Throws(IllegalStateException::class)
    override fun wrap(outgoing: ByteArray, offset: Int, len: Int): ByteArray {
        if (!complete)
            throw IllegalStateException("Authentication exchange has not completed")
        return Arrays.copyOfRange(outgoing, offset, offset + len)
    }

    @Throws(SaslException::class)
    override fun dispose() {
    }

    class PlainSaslServerFactory : SaslServerFactory {

        @Throws(SaslException::class)
        override fun createSaslServer(mechanism: String, protocol: String, serverName: String, props: Map<String, *>, cbh: CallbackHandler): SaslServer {

            if (PLAIN_MECHANISM != mechanism)
                throw SaslException(String.format("Mechanism \'%s\' is not supported. Only PLAIN is supported.", mechanism))

/*TTN            if (cbh !is SaslServerCallbackHandler)
                throw SaslException("CallbackHandler must be of type SaslServerCallbackHandler, but it is: " + cbh.javaClass)*/

//TTN            return PlainSaslServer(cbh.jaasContext())
            return PlainSaslServer()
        }

        override fun getMechanismNames(props: Map<String, *>?): Array<String> {
            if (props == null) return arrayOf(PLAIN_MECHANISM)
            val noPlainText = props[Sasl.POLICY_NOPLAINTEXT] as String
            return if ("true" == noPlainText)
                arrayOf()
            else
                arrayOf(PLAIN_MECHANISM)
        }
    }

    companion object {

        val PLAIN_MECHANISM = "PLAIN"
        //TTN private val JAAS_USER_PREFIX = "user_"
    }
}