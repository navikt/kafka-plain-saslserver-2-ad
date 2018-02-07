package org.navit.common.security.ldap

import org.amshove.kluent.`should be false`
import org.amshove.kluent.`should be true`
import org.jetbrains.spek.api.Spek
import org.jetbrains.spek.api.dsl.*
import org.navit.common.security.common.InMemoryLDAPServer
import org.navit.common.security.common.JAASContext

object LDAPAuthorizationSpec : Spek({

    // set the JAAS config in order to do successful init of LDAPAuthorization
    JAASContext.setUp()

    describe("LDAPAuthorization class test specifications") {

        beforeGroup {
            InMemoryLDAPServer.start()
        }

        given("correct path to correct YAML config - verification of membership") {

            // using classpath

            on("user and membership group") {
                it("should return true") {
                    val ldap = LDAPAuthorization.init()
                    ldap.isUserMemberOfAny("bdoe", listOf("ktACons")).`should be true`()
                }
            }
            on("user and non-membership group") {
                it("should return false") {
                    val ldap = LDAPAuthorization.init()
                    ldap.isUserMemberOfAny("adoe", listOf("ktACons")).`should be false`()
                }
            }
            on("user and membership group") {
                it("should return true") {
                    val ldap = LDAPAuthorization.init()
                    ldap.isUserMemberOfAny("adoe", listOf("ktAProd")).`should be true`()
                }
            }
            on("invalid user and existing group") {
                it("should return false") {
                    val ldap = LDAPAuthorization.init()
                    ldap.isUserMemberOfAny("invalid", listOf("ktACons")).`should be false`()
                }
            }
            on("existing user and invalid group") {
                it("should return false") {
                    val ldap = LDAPAuthorization.init()
                    ldap.isUserMemberOfAny("bdoe", listOf("invalid")).`should be false`()
                }
            }
            on("user and {invalid group,membership group}") {
                it("should return true") {
                    val ldap = LDAPAuthorization.init()
                    ldap.isUserMemberOfAny("bdoe", listOf("invalid","ktACons")).`should be true`()
                }
            }
            on("user and {non-membership group,membership group}") {
                it("should return true") {
                    val ldap = LDAPAuthorization.init()
                    ldap.isUserMemberOfAny("bdoe", listOf("ktAProd","ktACons")).`should be true`()
                }
            }
            on("user and {non-membership group,invalid group}") {
                it("should return false") {
                    val ldap = LDAPAuthorization.init()
                    ldap.isUserMemberOfAny("bdoe", listOf("ktAProd","invalid")).`should be false`()
                }
            }
        }

        // all cases with grpBaseDN and the other parameters will return false... not tested

        afterGroup {
            InMemoryLDAPServer.stop()
        }
    }

})