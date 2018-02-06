package org.navit.common.security.ldap

import org.amshove.kluent.`should be false`
import org.amshove.kluent.`should be true`
import org.jetbrains.spek.api.Spek
import org.jetbrains.spek.api.dsl.*
import org.navit.common.security.common.InMemoryLDAPServer

object LDAPAuthenticationSpec : Spek({

    describe("LDAPAuthentication class test specifications") {

        beforeGroup {
            InMemoryLDAPServer.start()
        }

        given("correct path to different YAML configs and correct LDAP user,pwd") {

            on("yaml - correct") {
                it("should return true") {

                    val ldap = LDAPAuthentication.init("src/test/resources/adconfig.yaml")
                    ldap.canUserAuthenticate("adoe", "alice").`should be true`()
                }
            }
            on("yaml - invalid host") {
                it("should return false") {

                    val ldap = LDAPAuthentication.init("src/test/resources/adcInvalidHost.yaml")
                    ldap.canUserAuthenticate("adoe", "alice").`should be false`()
                }
            }
            on("yaml - invalid port") {
                it("should return false") {
                    val ldap = LDAPAuthentication.init("src/test/resources/adcInvalidPort.yaml")
                    ldap.canUserAuthenticate("adoe", "alice").`should be false`()
                }
            }
            on("yaml - invalid port type") {
                it("should return false") {
                    val ldap = LDAPAuthentication.init("src/test/resources/adcInvalidPortType.yaml")
                    ldap.canUserAuthenticate("adoe", "alice").`should be false`()
                }
            }
            // connTimeout follows the same logic as port - no testing

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
            on("yaml - invalid usrUid") {
                it("should return false") {
                    val ldap = LDAPAuthentication.init("src/test/resources/adcInvalidusrUid.yaml")
                    ldap.canUserAuthenticate("adoe", "alice").`should be false`()
                }
            }
            on("yaml - empty usrUid") {
                it("should return false") {
                    val ldap = LDAPAuthentication.init("src/test/resources/adcEmptyusrUid.yaml")
                    ldap.canUserAuthenticate("adoe", "alice").`should be false`()
                }
            }
            on("yaml - missing usrUid") {
                it("should return false") {
                    val ldap = LDAPAuthentication.init("src/test/resources/adcMissingusrUid.yaml")
                    ldap.canUserAuthenticate("adoe", "alice").`should be false`()
                }
            }

        }

        given("incorrect path to YAML config and correct user, pwd") {
            on("as given") {
                it("should return false") {
                    val ldap = LDAPAuthentication.init("src/test/resources/notexisting.yaml")
                    ldap.canUserAuthenticate("adoe", "alice").`should be false`()
                }
            }
        }

        given("correct path to correct YAML config - verification of user and pwd") {

            val correctYAML = "src/test/resources/adconfig.yaml"

            on("invalid user and correct pwd") {
                it("should return false") {
                    val ldap = LDAPAuthentication.init(correctYAML)
                    ldap.canUserAuthenticate("invalid", "alice").`should be false`()
                }
            }
            on("correct user and invalid pwd") {
                it("should return false") {
                    val ldap = LDAPAuthentication.init(correctYAML)
                    ldap.canUserAuthenticate("adoe", "invalid").`should be false`()
                }
            }
            on("correct user and pwd") {
                it("should return true") {
                    val ldap = LDAPAuthentication.init(correctYAML)
                    ldap.canUserAuthenticate("adoe", "alice").`should be true`()
                }
            }
        }

        given("empty string as config file path (test AD) - verification of user and pwd") {

            on("invalid user and correct pwd") {
                it("should return false") {
                    val ldap = LDAPAuthentication.init("")
                    ldap.canUserAuthenticate("invalid", "alice").`should be false`()
                }
            }
            on("correct user and invalid pwd") {
                it("should return false") {
                    val ldap = LDAPAuthentication.init("")
                    ldap.canUserAuthenticate("adoe", "invalid").`should be false`()
                }
            }
            on("correct user and pwd") {
                it("should return false") {
                    val ldap = LDAPAuthentication.init("")
                    ldap.canUserAuthenticate("adoe", "alice").`should be false`()
                }
            }
        }

        given("ClassLoader for config file path (test AD) - verification of user and pwd") {

            //will find adconfig.yaml resource under build/resources/adconfig.yaml...

            on("invalid user and correct pwd") {
                it("should return false") {
                    val ldap = LDAPAuthentication.init(ClassLoader.getSystemClassLoader().getResource("adconfig.yaml")?.path ?: "")
                    ldap.canUserAuthenticate("invalid", "alice").`should be false`()
                }
            }
            on("correct user and invalid pwd") {
                it("should return false") {
                    val ldap = LDAPAuthentication.init(ClassLoader.getSystemClassLoader().getResource("adconfig.yaml")?.path ?: "")
                    ldap.canUserAuthenticate("adoe", "invalid").`should be false`()
                }
            }
            on("correct user and pwd") {
                it("should return true") {
                    val ldap = LDAPAuthentication.init(ClassLoader.getSystemClassLoader().getResource("adconfig.yaml")?.path ?: "")
                    ldap.canUserAuthenticate("adoe", "alice").`should be true`()
                }
            }
        }

        afterGroup {
            InMemoryLDAPServer.stop()
        }
    }

})