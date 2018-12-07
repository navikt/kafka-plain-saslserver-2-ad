package no.nav.common.security.authentication

import no.nav.common.security.common.InMemoryLDAPServer
import no.nav.common.security.ldap.LDAPCache
import org.amshove.kluent.shouldEqualTo
import org.apache.kafka.common.security.plain.PlainAuthenticateCallback
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe
import javax.security.auth.callback.NameCallback

object SimpleLDAPAuthenticationSpec : Spek({

    describe("SimpleLDAPAuthentication test specifications") {

        beforeGroup {
            InMemoryLDAPServer.start()
            LDAPCache.invalidateAllBinds()
        }

        context("authentication should work correctly") {

            // kind of misuse of the prompt field in NameCallback... Ok in test context
            val tests = mapOf(
                    arrayOf(
                            NameCallback("invalid user and pwd", "dontexist"),
                            PlainAuthenticateCallback("wrong".toCharArray())
                    ) to false,
                    arrayOf(
                            NameCallback("correct user and pwd", "igroup"),
                            PlainAuthenticateCallback("itest".toCharArray())
                    ) to true,
                    arrayOf(
                            NameCallback("correct user and invalid pwd", "igroup"),
                            PlainAuthenticateCallback("wrong".toCharArray())
                    ) to false,
                    arrayOf(
                            NameCallback("correct user and pwd", "srvp01"),
                            PlainAuthenticateCallback("srvp01".toCharArray())
                    ) to true,
                    arrayOf(
                            NameCallback("correct user and pwd", "srvp02"),
                            PlainAuthenticateCallback("srvp02".toCharArray())
                    ) to true
            )

            tests.forEach { callbacks, result ->

                val user = (callbacks.first() as NameCallback).defaultName
                val pwd = (callbacks.last() as PlainAuthenticateCallback).password()

                it("should for $user with $pwd return $result") {

                    SimpleLDAPAuthentication().handle(callbacks)
                    (callbacks.last() as PlainAuthenticateCallback).authenticated() shouldEqualTo result
                }
            }
        }

        afterGroup {
            InMemoryLDAPServer.stop()
        }
    }
})