package no.nav.common.security.authentication

import no.nav.common.security.common.InMemoryLDAPServer
import org.amshove.kluent.`should be`
import org.apache.kafka.common.security.plain.PlainAuthenticateCallback
import org.jetbrains.spek.api.Spek
import org.jetbrains.spek.api.dsl.context
import org.jetbrains.spek.api.dsl.describe
import org.jetbrains.spek.api.dsl.it
import javax.security.auth.callback.NameCallback

object SimpleLDAPAuthenticationSpec : Spek({

    describe("SimpleLDAPAuthentication test specifications") {

        beforeGroup {
            InMemoryLDAPServer.start()
        }

        context("authentication should work correctly") {

            // kind of misuse of the prompt field in NameCallback... Ok in test context
            val tests = mapOf(
                    arrayOf(
                            NameCallback("invalid user and pwd", "dontexist"),
                            PlainAuthenticateCallback("wrong".toCharArray())
                    ) to false,
                    arrayOf(
                            NameCallback("correct user and pwd", "srvkafkabroker"),
                            PlainAuthenticateCallback("broker".toCharArray())
                    ) to true,
                    arrayOf(
                            NameCallback("correct user and invalid pwd", "srvkafkabroker"),
                            PlainAuthenticateCallback("wrong".toCharArray())
                    ) to false
            )

            tests.forEach { callbacks, result ->

                it("should for ${(callbacks.first() as NameCallback).prompt} return $result") {

                    SimpleLDAPAuthentication().handle(callbacks)
                    (callbacks.last() as PlainAuthenticateCallback).authenticated() `should be` result
                }
            }
        }

        afterGroup {
            InMemoryLDAPServer.stop()
        }
    }
})