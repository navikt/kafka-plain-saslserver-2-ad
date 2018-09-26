package no.nav.common.security.ldap

import org.amshove.kluent.`should be false`
import org.amshove.kluent.`should be true`
import org.jetbrains.spek.api.Spek
import no.nav.common.security.common.InMemoryLDAPServer
import no.nav.common.security.common.JAASContext
import org.jetbrains.spek.api.dsl.describe
import org.jetbrains.spek.api.dsl.given
import org.jetbrains.spek.api.dsl.it
import org.jetbrains.spek.api.dsl.on

object LDAPAuthorizationSpec : Spek({

    // set the JAAS config in order to do successful init of LDAPAuthorization
    JAASContext.setUp()

    describe("LDAPAuthorization class test specifications") {

        beforeGroup {
            InMemoryLDAPServer.start()
            LDAPCache.invalidateAllGroups()
        }

        given("Classpath to  YAML config - verification of membership") {

            on("user and membership group") {
                it("should return true") {
                    val ldap = LDAPAuthorization.init(java.util.UUID.randomUUID().toString())
                    ldap.isUserMemberOfAny(
                            "bdoe",
                            listOf("ktACons")).isNotEmpty().`should be true`()
                }
            }
            on("user and non-membership group") {
                it("should return false") {
                    val ldap = LDAPAuthorization.init(java.util.UUID.randomUUID().toString())
                    ldap.isUserMemberOfAny(
                            "adoe",
                            listOf("ktACons")).isNotEmpty().`should be false`()
                }
            }
            on("user and membership group") {
                it("should return true") {
                    val ldap = LDAPAuthorization.init(java.util.UUID.randomUUID().toString())
                    ldap.isUserMemberOfAny(
                            "adoe",
                            listOf("ktAProd")).isNotEmpty().`should be true`()
                }
            }
            on("invalid user and existing group") {
                it("should return false") {
                    val ldap = LDAPAuthorization.init(java.util.UUID.randomUUID().toString())
                    ldap.isUserMemberOfAny(
                            "invalid",
                            listOf("ktACons")).isNotEmpty().`should be false`()
                }
            }
            on("existing user and invalid group") {
                it("should return false") {
                    val ldap = LDAPAuthorization.init(java.util.UUID.randomUUID().toString())
                    ldap.isUserMemberOfAny(
                            "bdoe",
                            listOf("invalid")).isNotEmpty().`should be false`()
                }
            }
            on("user and {invalid group,membership group}") {
                it("should return true") {
                    val ldap = LDAPAuthorization.init(java.util.UUID.randomUUID().toString())
                    ldap.isUserMemberOfAny(
                            "bdoe",
                            listOf("invalid", "ktACons")).isNotEmpty().`should be true`()
                }
            }
            on("user and {non-membership group,membership group}") {
                it("should return true") {
                    val ldap = LDAPAuthorization.init(java.util.UUID.randomUUID().toString())
                    ldap.isUserMemberOfAny(
                            "bdoe",
                            listOf("ktAProd", "ktACons")).isNotEmpty().`should be true`()
                }
            }
            on("user and {membership group,non-membership group}") {
                it("should return true for srv user in sub group ApplAccounts") {
                    val ldap = LDAPAuthorization.init(java.util.UUID.randomUUID().toString())
                    ldap.isUserMemberOfAny(
                            "srvaltinnkanal",
                            listOf("ktAProd", "ktACons")).isNotEmpty().`should be true`()
                }
            }
            on("user and {non-membership group,invalid group}") {
                it("should return false") {
                    val ldap = LDAPAuthorization.init(java.util.UUID.randomUUID().toString())
                    ldap.isUserMemberOfAny(
                            "bdoe",
                            listOf("ktAProd", "invalid")).isNotEmpty().`should be false`()
                }
            }
        }

        given("YAML config with root grpBaseDN  - verification of membership") {

            val root = "src/test/resources/adcRootgrpBaseDN.yaml"

            on("user and membership group") {
                it("should return true") {
                    val ldap = LDAPAuthorization.init(java.util.UUID.randomUUID().toString(), root)
                    ldap.isUserMemberOfAny(
                            "bdoe",
                            listOf("ktACons")).isNotEmpty().`should be true`()
                }
            }
            on("user and non-membership group") {
                it("should return false") {
                    val ldap = LDAPAuthorization.init(java.util.UUID.randomUUID().toString(), root)
                    ldap.isUserMemberOfAny(
                            "adoe",
                            listOf("ktACons")).isNotEmpty().`should be false`()
                }
            }
            on("user and membership group") {
                it("should return true") {
                    val ldap = LDAPAuthorization.init(java.util.UUID.randomUUID().toString(), root)
                    ldap.isUserMemberOfAny(
                            "adoe",
                            listOf("ktAProd")).isNotEmpty().`should be true`()
                }
            }
            on("invalid user and existing group") {
                it("should return false") {
                    val ldap = LDAPAuthorization.init(java.util.UUID.randomUUID().toString(), root)
                    ldap.isUserMemberOfAny(
                            "invalid",
                            listOf("ktACons")).isNotEmpty().`should be false`()
                }
            }
            on("existing user and invalid group") {
                it("should return false") {
                    val ldap = LDAPAuthorization.init(java.util.UUID.randomUUID().toString(), root)
                    ldap.isUserMemberOfAny(
                            "bdoe",
                            listOf("invalid")).isNotEmpty().`should be false`()
                }
            }
            on("user and {invalid group,membership group}") {
                it("should return true") {
                    val ldap = LDAPAuthorization.init(java.util.UUID.randomUUID().toString(), root)
                    ldap.isUserMemberOfAny(
                            "bdoe",
                            listOf("invalid", "ktACons")).isNotEmpty().`should be true`()
                }
            }
            on("user and {non-membership group,membership group}") {
                it("should return true") {
                    val ldap = LDAPAuthorization.init(java.util.UUID.randomUUID().toString(), root)
                    ldap.isUserMemberOfAny(
                            "bdoe",
                            listOf("ktAProd", "ktACons")).isNotEmpty().`should be true`()
                }
            }
            on("user and {non-membership group,invalid group}") {
                it("should return false") {
                    val ldap = LDAPAuthorization.init(java.util.UUID.randomUUID().toString(), root)
                    ldap.isUserMemberOfAny(
                            "bdoe",
                            listOf("ktAProd", "invalid")).isNotEmpty().`should be false`()
                }
            }
        }

        // all cases with grpBaseDN and the other parameters will return false... not tested

        afterGroup {
            InMemoryLDAPServer.stop()
        }
    }
})