package no.nav.common.security.ldap

import no.nav.common.security.AuthenticationResult
import no.nav.common.security.common.InMemoryLDAPServer
import org.amshove.kluent.shouldEqual
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe

object LDAPBaseSpec : Spek({

    describe("LDAPBase class test specifications") {

        /**
         * Test scope
         * - Test correct and incorrect users in ServiceAccounts
         * - Test correct and incorrect users in ApplAccounts
         *
         * Good enough testing
         *
         * NOT testing a lot of different wrong configurations in yaml
         * invalid host, port, usrBaseDN, usrUid, ...
         * Those will return false anyway
         */

        beforeGroup {
            InMemoryLDAPServer.start()
            LDAPCache.invalidateAllBinds()
        }

        // users from both nodes, ServiceAccounts and ApplAccounts

        val refUsers = mapOf(
                Pair("srvp01", "srvp01") to AuthenticationResult.SuccessfulBind,
                Pair("srvc01", "srvc01") to AuthenticationResult.SuccessfulBind,
                Pair("srvp02", "srvp02") to AuthenticationResult.SuccessfulBind,
                Pair("srvc02", "srvc02") to AuthenticationResult.SuccessfulBind,
                Pair("srvp01", "invalidpwd") to AuthenticationResult.UnsuccessfulBind("LDAP bind exception for srvp01 - null"),
                Pair("srvp02", "invalidpwd") to AuthenticationResult.UnsuccessfulBind("LDAP bind exception for srvp02 - null"),
                Pair("invalid", "srvc01") to AuthenticationResult.UnsuccessfulBind("LDAP bind exception for invalid - The requested identity 'u:invalid' could not be mapped to a user defined in the server.")
        )

        context("correct path to default YAML config") {

            refUsers.forEach { user, result ->

                it("should return $result for user ${user.first} with pwd ${user.second}") {

                    val config = LDAPConfig.getBySource("src/test/resources/ldapconfig.yaml")
                    LDAPBase(config).authenticationOk(user.first, user.second) shouldEqual result
                }
            }
        }

        context("classpath to YAML config") {

            refUsers.forEach { user, result ->

                it("should return $result for user ${user.first} with pwd ${user.second}") {
                    LDAPBase().authenticationOk(user.first, user.second) shouldEqual result
                }
            }
        }

        afterGroup {
            InMemoryLDAPServer.stop()
        }
    }
})