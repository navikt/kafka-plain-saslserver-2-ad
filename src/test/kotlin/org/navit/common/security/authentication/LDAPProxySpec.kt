package org.navit.common.security.authentication

import com.unboundid.ldap.listener.InMemoryDirectoryServer
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig
import com.unboundid.ldap.listener.InMemoryListenerConfig
import org.amshove.kluent.`should be false`
import org.amshove.kluent.`should be true`
import org.jetbrains.spek.api.Spek
import org.jetbrains.spek.api.dsl.*

object LDAPProxySpec : Spek ({

    val imConf = InMemoryDirectoryServerConfig("dc=example,dc=com","dc=adeo,dc=example,dc=com")

    imConf.setListenerConfigs(
            InMemoryListenerConfig.createLDAPConfig("LDAP",11389)
    )
    val imDS = InMemoryDirectoryServer(imConf)

    imDS.importFromLDIF(true,"src/test/resources/ADUsers.ldif")

    describe("LDAPProxy class test specifications") {

        beforeGroup {
            imDS.startListening("LDAP")
        }

        given("correct path to different YAML configs and correct user,pwd") {

            on("yaml - correct") {
                it("should return true") {

                    val ldap = LDAPProxy.init("src/test/resources/adconfig.yaml")
                    ldap.canUserAuthenticate("adoe", "alice").`should be true`()
                }
            }
            on("yaml - invalid host") {
                it("should return false") {

                    val ldap = LDAPProxy.init("src/test/resources/adcInvalidHost.yaml")
                    ldap.canUserAuthenticate("adoe", "alice").`should be false`()
                }
            }
            on("yaml - invalid port") {
                it("should return false") {
                    val ldap = LDAPProxy.init("src/test/resources/adcInvalidPort.yaml")
                    ldap.canUserAuthenticate("adoe", "alice").`should be false`()
                }
            }
            on("yaml - invalid usrBaseDN") {
                it("should return false") {
                    val ldap = LDAPProxy.init("src/test/resources/adcInvalidusrBaseDN.yaml")
                    ldap.canUserAuthenticate("adoe", "alice").`should be false`()
                }
            }
            on("yaml - empty usrBaseDN") {
                it("should return false") {
                    val ldap = LDAPProxy.init("src/test/resources/adcEmptyusrBaseDN.yaml")
                    ldap.canUserAuthenticate("adoe", "alice").`should be false`()
                }
            }
            on("yaml - missing usrBaseDN") {
                it("should return false") {
                    val ldap = LDAPProxy.init("src/test/resources/adcMissingusrBaseDN.yaml")
                    ldap.canUserAuthenticate("adoe", "alice").`should be false`()
                }
            }
            on("yaml - invalid UID") {
                it("should return false") {
                    val ldap = LDAPProxy.init("src/test/resources/adcInvalidusrUid.yaml")
                    ldap.canUserAuthenticate("adoe", "alice").`should be false`()
                }
            }
            on("yaml - empty UID") {
                it("should return false") {
                    val ldap = LDAPProxy.init("src/test/resources/adcEmptyusrUid.yaml")
                    ldap.canUserAuthenticate("adoe", "alice").`should be false`()
                }
            }
            on("yaml - missing UID") {
                it("should return false") {
                    val ldap = LDAPProxy.init("src/test/resources/adcMissingusrUid.yaml")
                    ldap.canUserAuthenticate("adoe", "alice").`should be false`()
                }
            }

        }

        given("incorrect path to YAML config and correct user, pwd") {
            on("as given") {
                it("should return false") {
                    val ldap = LDAPProxy.init("src/test/resources/notexisting.yaml")
                    ldap.canUserAuthenticate("adoe", "alice").`should be false`()
                }
            }
        }

        given("correct path to correct YAML config - verification of user and pwd") {

            val correctYAML = "src/test/resources/adconfig.yaml"

            on("invalid user and correct pwd") {
                it("should return false") {
                    val ldap = LDAPProxy.init(correctYAML)
                    ldap.canUserAuthenticate("invalid", "alice").`should be false`()
                }
            }
            on("correct user and invalid pwd") {
                it("should return false") {
                    val ldap = LDAPProxy.init(correctYAML)
                    ldap.canUserAuthenticate("adoe", "invalid").`should be false`()
                }
            }
            on("correct user and pwd") {
                it("should return true") {
                    val ldap = LDAPProxy.init(correctYAML)
                    ldap.canUserAuthenticate("adoe", "alice").`should be true`()
                }
            }
        }

        given("empty string as config file path (test AD) - verification of user and pwd") {

            on("invalid user and correct pwd") {
                it("should return false") {
                    val ldap = LDAPProxy.init("")
                    ldap.canUserAuthenticate("invalid", "alice").`should be false`()
                }
            }
            on("correct user and invalid pwd") {
                it("should return false") {
                    val ldap = LDAPProxy.init("")
                    ldap.canUserAuthenticate("adoe", "invalid").`should be false`()
                }
            }
            on("correct user and pwd") {
                it("should return false") {
                    val ldap = LDAPProxy.init("")
                    ldap.canUserAuthenticate("adoe", "alice").`should be false`()
                }
            }
        }

        given("ClassLoader for config file path (test AD) - verification of user and pwd") {

            //will find adconfig.yaml resource under build/resources/adconfig.yaml...

            on("invalid user and correct pwd") {
                it("should return false") {
                    val ldap = LDAPProxy.init(ClassLoader.getSystemClassLoader().getResource("adconfig.yaml")?.path ?: "")
                    ldap.canUserAuthenticate("invalid", "alice").`should be false`()
                }
            }
            on("correct user and invalid pwd") {
                it("should return false") {
                    val ldap = LDAPProxy.init(ClassLoader.getSystemClassLoader().getResource("adconfig.yaml")?.path ?: "")
                    ldap.canUserAuthenticate("adoe", "invalid").`should be false`()
                }
            }
            on("correct user and pwd") {
                it("should return true") {
                    val ldap = LDAPProxy.init(ClassLoader.getSystemClassLoader().getResource("adconfig.yaml")?.path ?: "")
                    ldap.canUserAuthenticate("adoe", "alice").`should be true`()
                }
            }
        }

        given("correct path to correct YAML config - verification of membership") {

            val correctYAML = "src/test/resources/adconfig.yaml"

            on("user and membership group") {
                it("should return true") {
                    val ldap = LDAPProxy.init(correctYAML)
                    ldap.isUserMemberOfAny("bdoe", listOf("ktACons")).`should be true`()
                }
            }
            on("user and non-membership group") {
                it("should return false") {
                    val ldap = LDAPProxy.init(correctYAML)
                    ldap.isUserMemberOfAny("adoe", listOf("ktACons")).`should be false`()
                }
            }
            on("user and membership group") {
                it("should return true") {
                    val ldap = LDAPProxy.init(correctYAML)
                    ldap.isUserMemberOfAny("adoe", listOf("ktAProd")).`should be true`()
                }
            }
            on("invalid user and existing group") {
                it("should return false") {
                    val ldap = LDAPProxy.init(correctYAML)
                    ldap.isUserMemberOfAny("invalid", listOf("ktACons")).`should be false`()
                }
            }
            on("existing user and invalid group") {
                it("should return false") {
                    val ldap = LDAPProxy.init(correctYAML)
                    ldap.isUserMemberOfAny("bdoe", listOf("invalid")).`should be false`()
                }
            }
            on("user and {invalid group,membership group}") {
                it("should return true") {
                    val ldap = LDAPProxy.init(correctYAML)
                    ldap.isUserMemberOfAny("bdoe", listOf("invalid","ktACons")).`should be true`()
                }
            }
            on("user and {non-membership group,membership group}") {
                it("should return true") {
                    val ldap = LDAPProxy.init(correctYAML)
                    ldap.isUserMemberOfAny("bdoe", listOf("ktAProd","ktACons")).`should be true`()
                }
            }
            on("user and {non-membership group,invalid group}") {
                it("should return false") {
                    val ldap = LDAPProxy.init(correctYAML)
                    ldap.isUserMemberOfAny("bdoe", listOf("ktAProd","invalid")).`should be false`()
                }
            }
        }

        afterGroup {
            imDS.shutDown(true)
        }

    }

})