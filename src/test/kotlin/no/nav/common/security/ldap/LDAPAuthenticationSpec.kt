package no.nav.common.security.ldap

import org.amshove.kluent.`should be false`
import org.amshove.kluent.`should be true`
import org.jetbrains.spek.api.Spek
import org.jetbrains.spek.api.dsl.*
import no.nav.common.security.common.InMemoryLDAPServer

object LDAPAuthenticationSpec : Spek({

    describe("LDAPAuthentication class test specifications") {

        beforeGroup {
            InMemoryLDAPServer.start()
        }

        given("correct path to different YAML configs and correct LDAP user,pwd") {

            on("yaml - invalid host") {
                it("should return true") {

                    val ldap = LDAPAuthentication.init("src/test/resources/adcInvalidHost.yaml")
                    ldap.canUserAuthenticate("adoe", "alice").`should be false`()
                }
            }

            on("yaml - correct") {
                it("should return true") {

                    val ldap = LDAPAuthentication.init("src/test/resources/adconfig.yaml")
                    ldap.canUserAuthenticate("adoe", "alice").`should be true`()
                }
            }
            on("yaml - invalid usrBaseDN") {
                it("should return false") {
                    val ldap = LDAPAuthentication.init("src/test/resources/adcInvalidusrBaseDN.yaml")
                    ldap.canUserAuthenticate("adoe", "alice").`should be false`()
                }
            }
            on("yaml - empty usrBaseDN") {
                it("should return false") {
                    val ldap = LDAPAuthentication.init("src/test/resources/adcEmptyusrBaseDN.yaml")
                    ldap.canUserAuthenticate("adoe", "alice").`should be false`()
                }
            }
            on("yaml - missing usrBaseDN") {
                it("should return false") {
                    val ldap = LDAPAuthentication.init("src/test/resources/adcMissingusrBaseDN.yaml")
                    ldap.canUserAuthenticate("adoe", "alice").`should be false`()
                }
            }
            on("yaml - usrBaseDN as root of tree") {
                it("should return false") {
                    val ldap = LDAPAuthentication.init("src/test/resources/adcRootusrBaseDN.yaml")
                    ldap.canUserAuthenticate("adoe", "alice").`should be false`()
                }
            }
            on("yaml - invalid usrUid") {
                it("should return false") {
                    val ldap = LDAPAuthentication.init("src/test/resources/adcInvalidusrUid.yaml")
                    ldap.canUserAuthenticate("adoe", "alice").`should be false`()
                }
            }
            on("yaml - empty usrUid") {
                it("should return false") {
                    val ldap = LDAPAuthentication.init("src/test/resources/adcEmptyusrBaseDN.yaml")
                    ldap.canUserAuthenticate("adoe", "alice").`should be false`()
                }
            }
            on("yaml - missing usrUid") {
                it("should return false") {
                    val ldap = LDAPAuthentication.init("src/test/resources/adcMissingusrBaseDN.yaml")
                    ldap.canUserAuthenticate("adoe", "alice").`should be false`()
                }
            }

        }

        given("incorrect path to YAML config and correct user, pwd") {
            on("as given") {
                it("should return false") {
                    val ldap = LDAPAuthentication.init("invalid.yaml")
                    ldap.canUserAuthenticate("adoe", "alice").`should be false`()
                }
            }
        }

        given("classpath to YAML config - verification of user and pwd") {

            on("invalid user and correct pwd") {
                it("should return false") {
                    val ldap = LDAPAuthentication.init()
                    ldap.canUserAuthenticate("invalid", "alice").`should be false`()
                }
            }
            on("correct user and invalid pwd") {
                it("should return false") {
                    val ldap = LDAPAuthentication.init()
                    ldap.canUserAuthenticate("adoe", "invalid").`should be false`()
                }
            }
            on("correct user and pwd") {
                it("should return true") {
                    val ldap = LDAPAuthentication.init()
                    ldap.canUserAuthenticate("adoe", "alice").`should be true`()
                }
            }
        }

        afterGroup {
            InMemoryLDAPServer.stop()
        }
    }

})