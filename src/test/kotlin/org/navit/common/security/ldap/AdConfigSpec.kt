package org.navit.common.security.ldap

import org.amshove.kluent.`should be equal to`
import org.jetbrains.spek.api.Spek
import org.jetbrains.spek.api.dsl.describe
import org.jetbrains.spek.api.dsl.given
import org.jetbrains.spek.api.dsl.it
import org.jetbrains.spek.api.dsl.on

object AdConfigSpec : Spek({

    describe("LDAPAuthentication class test specifications") {

        beforeGroup {}

        given("correct path to different YAML configs") {

            on("yaml - correct") {

                val config = ADConfig.getBySource("src/test/resources/adconfig.yaml")

                it("should return 10 items") {
                    config.size.`should be equal to`(10)
                }
                it("should return host as localhost") {
                    config["host"].toString().`should be equal to`("localhost")
                }
                it("should return port as 11636"){
                    config["port"].toString().toInt().`should be equal to`(11636)
                }
                it("should return connTimeout as 500"){
                    config["connTimeout"].toString().toInt().`should be equal to`(500)
                }
                it("should return usrUid as uid") {
                    config["usrUid"].toString().`should be equal to`("uid")
                }
                it("should return grpUid as cn"){
                    config["grpUid"].toString().`should be equal to`("cn")
                }
                it("should return grpCacheExpire as 12"){
                    config["grpCacheExpire"].toString().toInt().`should be equal to`(12)
                }
            }
            on("yaml - invalid port type") {

                val config = ADConfig.getBySource("src/test/resources/adcInvalidPortType.yaml")

                it("should return port as 0") {
                    config["port"].toString().toInt().`should be equal to`(0)
                }

                // all the other INT based parameters use same logic - not testing those
            }
            on("yaml - missing port") {

                val config = ADConfig.getBySource("src/test/resources/adcMissingPort.yaml")

                it("should return port as 0") {
                    config["port"].toString().toInt().`should be equal to`(0)
                }

                // all the other INT based parameters use same logic - not testing those
            }
            on("yaml - empty usrUid") {

                val config = ADConfig.getBySource("src/test/resources/adcEmptyusrUid.yaml")

                it("should return usrUid as empty string"){
                    config["usrUid"].toString().`should be equal to`("")
                }
            }
            on("yaml - missing usrUid") {

                val config = ADConfig.getBySource("src/test/resources/adcMissingusrUid.yaml")

                it("should return usrUid as string 'null'"){
                    config["usrUid"].toString().`should be equal to`("null")
                }
            }
        }

        given("incorrect path to YAML config") {

            on("no file found, use default values") {

                val config = ADConfig.getBySource("invalid.yaml")

                it("should return 10 items") {
                    config.size.`should be equal to`(10)
                }
                it("should return host as empty string") {
                    config["host"].toString().`should be equal to`("")
                }
                it("should return port as 0"){
                    config["port"].toString().toInt().`should be equal to`(0)
                }
                it("should return connTimeout as 3000"){
                    config["connTimeout"].toString().toInt().`should be equal to`(3000)
                }
                it("should return usrUid as empty string") {
                    config["usrUid"].toString().`should be equal to`("")
                }
                it("should return grpCacheExpire as 12"){
                    config["grpCacheExpire"].toString().toInt().`should be equal to`(12)
                }

            }

        }

        given("ClassLoader for config file path") {

            //will find adconfig.yaml resource under build/resources/adconfig.yaml...

            val config = ADConfig.getByClasspath()

            it("should return 10 items") {
                config.size.`should be equal to`(10)
            }
            it("should return host as localhost") {
                config["host"].toString().`should be equal to`("localhost")
            }
            it("should return port as 11636"){
                config["port"].toString().toInt().`should be equal to`(11636)
            }
            it("should return connTimeout as 500"){
                config["connTimeout"].toString().toInt().`should be equal to`(500)
            }
            it("should return usrUid as uid") {
                config["usrUid"].toString().`should be equal to`("uid")
            }
            it("should return grpUid as cn"){
                config["grpUid"].toString().`should be equal to`("cn")
            }
            it("should return grpCacheExpire as 12"){
                config["grpCacheExpire"].toString().toInt().`should be equal to`(12)
            }
        }

        afterGroup {}
    }
})