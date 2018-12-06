package no.nav.common.security.ldap

import org.amshove.kluent.shouldEqual
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe

object LDAPConfigSpec : Spek({

    describe("LDAPConfig class test specifications") {

        val refLDAPConfig = LDAPConfig.Config(
                "localhost",
                11636,
                500,
                "ou=ServiceAccounts,dc=test,dc=local",
                "uid",
                "ou=Groups,ou=NAV,ou=BusinessUnits,dc=test,dc=local",
                "cn",
                "member",
                2,
                4)

        context("getBySource - correct path to different YAML configs") {

            val refLDAPConfigOther = LDAPConfig.Config(
                    "host",
                    11636,
                    500,
                    "usrbasedn",
                    "usruid",
                    "grpbasedn",
                    "grpuid",
                    "grpattrname",
                    2,
                    4)

            val yamlFiles = mapOf(
                    Pair("correct content", "src/test/resources/ldapconfig.yaml") to refLDAPConfig,
                    Pair("correct content", "src/test/resources/ldapconfigother.yaml") to refLDAPConfigOther,
                    Pair("empty config", "src/test/resources/ldapconfigpartial.yaml") to LDAPConfig.emptyConfig
            )

            yamlFiles.forEach { pair, refConfig ->
                it("should return ${pair.first} for ${pair.second}") {
                    LDAPConfig.getBySource(pair.second) shouldEqual refConfig
                }
            }
        }

        context("getBySource - incorrect path to YAML config") {

            it("should return empty config") {
                LDAPConfig.getBySource("invalid.yaml") shouldEqual LDAPConfig.emptyConfig
            }
        }

        context("getByClasspath - load of default yaml config") {

            it("should return default yaml config") {
                // will find ldapconfig.yaml resource under build/resources/ldapconfig.yaml...
                LDAPConfig.getByClasspath() shouldEqual refLDAPConfig
            }
        }
    }
})