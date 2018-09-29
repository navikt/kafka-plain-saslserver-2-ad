package no.nav.common.security.ldap

import no.nav.common.security.common.InMemoryLDAPServer
import no.nav.common.security.common.JAASContext
import org.amshove.kluent.shouldEqual
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe

object LDAPAuthorizationSpec : Spek({

    // set the JAAS config in order to do successful init of LDAPAuthorization
    JAASContext.setUp()

    describe("LDAPAuthorization class test specifications") {

        /**
         * Test scope
         * Group membership must be tested for 2 different group - and 2 user levels
         * group levels - AccountGroupNotInRemedy and kafka
         * user levels - ServiceAccounts and ApplAccounts
         *
         * Good enough testing
         *
         * NOT testing a lot of different wrong configurations in yaml
         * invalid host, port, grpBaseDN, ...
         * Those will return 0 anyway
         */

        beforeGroup {
            InMemoryLDAPServer.start()
            LDAPCache.invalidateAllGroups()
        }

        val refUserGroup = mapOf(
                Pair("srvc01", listOf("rmy-01")) to 1,
                Pair("srvc02", listOf("rmy-02")) to 1,
                Pair("srvp01", listOf("rmy-01", "rmy-02")) to 1,
                Pair("srvp02", listOf("rmy-02", "rmy-01")) to 0,
                Pair("srvp01", listOf("KC-tpc-02", "KP-tpc-02")) to 1,
                Pair("srvc02", listOf("KC-tpc-02", "rmy-02")) to 2,
                Pair("srvp02", listOf("KC-tpc-02", "rmy-02", "KP-tpc-03")) to 1,
                Pair("srvc02", listOf("KC-tpc-02", "rmy-02", "KP-tpc-03")) to 2
        )

        describe("correct path to default YAML config") {

            refUserGroup.forEach { usrGrp, size ->

                it("should return $size membership(s) for user ${usrGrp.first} in ${usrGrp.second}") {
                    LDAPAuthorization.init(
                            java.util.UUID.randomUUID().toString(),
                            "src/test/resources/ldapconfig.yaml")
                            .isUserMemberOfAny(usrGrp.first, usrGrp.second).size shouldEqual size
                }
            }
        }

        describe("classpath to  YAML config") {

            refUserGroup.forEach { usrGrp, size ->

                it("should return $size membership(s) for user ${usrGrp.first} in ${usrGrp.second}") {
                    LDAPAuthorization.init(java.util.UUID.randomUUID().toString())
                            .isUserMemberOfAny(usrGrp.first, usrGrp.second).size shouldEqual size
                }
            }
        }

        afterGroup {
            InMemoryLDAPServer.stop()
        }
    }
})