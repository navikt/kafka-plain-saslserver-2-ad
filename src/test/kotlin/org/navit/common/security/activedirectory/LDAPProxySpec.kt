package org.navit.common.security.activedirectory

import com.unboundid.ldap.sdk.ResultCode
import org.amshove.kluent.`should equal`
import org.jetbrains.spek.api.Spek
import org.jetbrains.spek.api.dsl.given
import org.jetbrains.spek.api.dsl.it
import org.jetbrains.spek.api.dsl.on

object LDAPProxySpec : Spek ({

    given("correct path to YAML config and correct user,pwd") {

        on("yaml - correct") {
            it("should return success") {

                val ldap = LDAPProxy.init("src/test/resources/adconfig.yaml")
                ldap.verifyUserAndPassword("adoe","alice").`should equal`(ResultCode.SUCCESS)
            }
        }
        on("yaml - invalid host") {
            it("should return connection error") {

                val ldap = LDAPProxy.init("src/test/resources/adcInvalidHost.yaml")
                ldap.verifyUserAndPassword("adoe","alice").`should equal`(ResultCode.CONNECT_ERROR)
            }
        }
        on("yaml - invalid port") {
            it("should return connection error") {
                val ldap = LDAPProxy.init("src/test/resources/adcInvalidPort.yaml")
                ldap.verifyUserAndPassword("adoe","alice").`should equal`(ResultCode.CONNECT_ERROR)
            }
        }
        on("yaml - invalid baseDN") {
            it("should return no such object") {
                val ldap = LDAPProxy.init("src/test/resources/adcInvalidBaseDN.yaml")
                ldap.verifyUserAndPassword("adoe","alice").`should equal`(ResultCode.NO_SUCH_OBJECT)
            }
        }
        on("yaml - empty baseDN") {
            it("should return success") {
                val ldap = LDAPProxy.init("src/test/resources/adcEmptyBaseDN.yaml")
                ldap.verifyUserAndPassword("adoe","alice").`should equal`(ResultCode.SUCCESS)
            }
        }
        on("yaml - missing baseDN") {
            it("should return success") {
                val ldap = LDAPProxy.init("src/test/resources/adcMissingBaseDN.yaml")
                ldap.verifyUserAndPassword("adoe","alice").`should equal`(ResultCode.SUCCESS)
            }
        }
        on("yaml - invalid filter") {
            it("should return filter error") {
                val ldap = LDAPProxy.init("src/test/resources/adcInvalidFilter.yaml")
                ldap.verifyUserAndPassword("adoe","alice").`should equal`(ResultCode.FILTER_ERROR)
            }
        }
        on("yaml - empty filter") {
            it("should return success") {
                val ldap = LDAPProxy.init("src/test/resources/adcEmptyFilter.yaml")
                ldap.verifyUserAndPassword("adoe","alice").`should equal`(ResultCode.SUCCESS)
            }
        }
        on("yaml - too tight filter") {
            it("should return inappropriate matchin") {
                val ldap = LDAPProxy.init("src/test/resources/adcClosedFilter.yaml")
                ldap.verifyUserAndPassword("adoe","alice").`should equal`(ResultCode.INAPPROPRIATE_MATCHING)
            }
        }
        on("yaml - missing filter") {
            it("should return success") {
                val ldap = LDAPProxy.init("src/test/resources/adcMissingFilter.yaml")
                ldap.verifyUserAndPassword("adoe","alice").`should equal`(ResultCode.SUCCESS)
            }
        }
    }

    given("incorrect path to YAML config and correct user, pwd") {
        on("as given") {
            it("should return connection error") {
                val ldap = LDAPProxy.init("src/test/resources/notexisting.yaml")
                ldap.verifyUserAndPassword("adoe","alice").`should equal`(ResultCode.CONNECT_ERROR)

            }
        }
    }

    given("correct path to correct YAML config - verification of user and pwd") {

        val ldap = LDAPProxy.init("src/test/resources/adconfig.yaml")

        on("invalid user and correct pwd") {
            it("should return inappropriate matching") {
                ldap.verifyUserAndPassword("invalid","alice").`should equal`(ResultCode.INAPPROPRIATE_MATCHING)
            }
        }
        on("correct user and invalid pwd") {
            it("should return inappropriate matching") {
                ldap.verifyUserAndPassword("adoe","invalid").`should equal`(ResultCode.INVALID_CREDENTIALS)
            }
        }
        on("correct user and pwd") {
            it("should return inappropriate matching") {
                ldap.verifyUserAndPassword("adoe","alice").`should equal`(ResultCode.SUCCESS)
            }
        }
    }

    given("empty string as config file path (test AD) - verification of user and pwd") {

        val ldap = LDAPProxy.init("")

        on("invalid user and correct pwd") {
            it("should return inappropriate matching") {
                ldap.verifyUserAndPassword("invalid","alice").`should equal`(ResultCode.CONNECT_ERROR)
            }
        }
        on("correct user and invalid pwd") {
            it("should return inappropriate matching") {
                ldap.verifyUserAndPassword("adoe","invalid").`should equal`(ResultCode.CONNECT_ERROR)
            }
        }
        on("correct user and pwd") {
            it("should return inappropriate matching") {
                ldap.verifyUserAndPassword("adoe","alice").`should equal`(ResultCode.CONNECT_ERROR)
            }
        }
    }

})