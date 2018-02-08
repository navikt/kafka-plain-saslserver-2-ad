package no.nav.common.security.ldap

import org.amshove.kluent.`should be equal to`
import org.jetbrains.spek.api.Spek
import org.jetbrains.spek.api.dsl.describe
import org.jetbrains.spek.api.dsl.given
import org.jetbrains.spek.api.dsl.it
import org.jetbrains.spek.api.dsl.on

object AdConfigSpec : Spek({

    describe("LDAPAuthentication class test specifications") {

        beforeGroup {}

        given("getBySource - correct path to different YAML configs") {

            on("yaml - default file") {

                val config = ADConfig.getBySource("src/test/resources/adconfig.yaml")

                it("should return host as localhost") {
                    config.host.`should be equal to`("localhost")
                }
                it("should return port as 11636"){
                    config.port.`should be equal to`(11636)
                }
                it("should return connTimeout as 500"){
                    config.connTimeout.`should be equal to`(500)
                }
                it("should return usrBaseDN as ou=ServiceAccounts,dc=adeo,dc=example,dc=com") {
                    config.usrBaseDN.`should be equal to`("ou=ServiceAccounts,dc=adeo,dc=example,dc=com")
                }
                it("should return usrUid as uid") {
                    config.usrUid.`should be equal to`("uid")
                }
                it("should return grpBaseDN as ou=KafkaGroups,dc=adeo,dc=example,dc=com"){
                    config.grpBaseDN.`should be equal to`("ou=KafkaGroups,dc=adeo,dc=example,dc=com")
                }
                it("should return grpUid as cn"){
                    config.grpUid.`should be equal to`("cn")
                }
                it("should return grpAttrName as uniqueMember"){
                    config.grpAttrName.`should be equal to`("uniqueMember")
                }
                it("should return usrCacheExpire as 12"){
                    config.usrCacheExpire.`should be equal to`(12)
                }
                it("should return grpCacheExpire as 12"){
                    config.grpCacheExpire.`should be equal to`(12)
                }
            }
            on("yaml - invalid port type") {

                // will return default value

                val config = ADConfig.getBySource("src/test/resources/adcInvalidPortType.yaml")

                it("should return port as 0") {
                    config.port.`should be equal to`(0)
                }

                // all the other INT based parameters use same logic - not testing of those
            }
            on("yaml - missing port") {

                // will return default value

                val config = ADConfig.getBySource("src/test/resources/adcMissingPort.yaml")

                it("should return port as 0") {
                    config.port.`should be equal to`(0)
                }
            }
            on("yaml - empty usrUid") {

                // will return default value

                val config = ADConfig.getBySource("src/test/resources/adcEmptyusrUid.yaml")

                it("should return usrUid as empty"){
                    config.usrUid.`should be equal to`("")
                }
            }
            on("yaml - missing usrUid") {

                // will return default value

                val config = ADConfig.getBySource("src/test/resources/adcMissingusrUid.yaml")

                it("should return usrUid as empty"){
                    config.usrUid.`should be equal to`("")
                }
            }

            // all the other parameters use same logic - not testing those
        }

        given("getBySource - incorrect path to YAML config") {

            on("no file found, use default values") {

                val config = ADConfig.getBySource("invalid.yaml")

                it("should return host as empty") {
                    config.host.`should be equal to`("")
                }
                it("should return port as 0"){
                    config.port.`should be equal to`(0)
                }
                it("should return connTimeout as 3000"){
                    config.connTimeout.`should be equal to`(3000)
                }
                it("should return usrBaseDN as empty") {
                    config.usrBaseDN.`should be equal to`("")
                }
                it("should return usrUid as empty") {
                    config.usrUid.`should be equal to`("")
                }
                it("should return grpBaseDN as empty"){
                    config.grpBaseDN.`should be equal to`("")
                }
                it("should return grpUid as empty"){
                    config.grpUid.`should be equal to`("")
                }
                it("should return grpAttrName as empty"){
                    config.grpAttrName.`should be equal to`("")
                }
                it("should return usrCacheExpire as 12"){
                    config.usrCacheExpire.`should be equal to`(12)
                }
                it("should return grpCacheExpire as 12"){
                    config.grpCacheExpire.`should be equal to`(12)
                }

            }

        }

        given("getByClasspath - load of default yaml config") {

            //will find adconfig.yaml resource under build/resources/adconfig.yaml...

            val config = ADConfig.getByClasspath()

            on("yaml - default file") {

                it("should return host as localhost") {
                    config.host.`should be equal to`("localhost")
                }
                it("should return port as 11636"){
                    config.port.`should be equal to`(11636)
                }
                it("should return connTimeout as 500"){
                    config.connTimeout.`should be equal to`(500)
                }
                it("should return usrBaseDN as ou=ServiceAccounts,dc=adeo,dc=example,dc=com") {
                    config.usrBaseDN.`should be equal to`("ou=ServiceAccounts,dc=adeo,dc=example,dc=com")
                }
                it("should return usrUid as uid") {
                    config.usrUid.`should be equal to`("uid")
                }
                it("should return grpBaseDN as ou=KafkaGroups,dc=adeo,dc=example,dc=com"){
                    config.grpBaseDN.`should be equal to`("ou=KafkaGroups,dc=adeo,dc=example,dc=com")
                }
                it("should return grpUid as cn"){
                    config.grpUid.`should be equal to`("cn")
                }
                it("should return grpAttrName as uniqueMember"){
                    config.grpAttrName.`should be equal to`("uniqueMember")
                }
                it("should return usrCacheExpire as 12"){
                    config.usrCacheExpire.`should be equal to`(12)
                }
                it("should return grpCacheExpire as 12"){
                    config.grpCacheExpire.`should be equal to`(12)
                }
            }

        }

        afterGroup {}
    }
})