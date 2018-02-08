package no.nav.common.security.ldap

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory
import com.fasterxml.jackson.module.kotlin.KotlinModule
import org.slf4j.LoggerFactory
import java.nio.file.Files
import java.nio.file.Paths

/**
 * A Singleton class returning a data class for all config parameters
 * The configuration can be loaded in two different ways
 * - by source, used in test scenarios
 * - by classpath, used when running of kafka brokers
 *
 * See test/resources/adconfig.yaml for 1:1 mapping between YAML and data class
 */

object ADConfig {

    data class Config(
            val host: String,
            val port: Int,
            val connTimeout: Int,
            val usrBaseDN: String,
            val usrUid: String,
            val grpBaseDN: String,
            val grpUid: String,
            val grpAttrName:String,
            val usrCacheExpire: Int,
            val grpCacheExpire: Int
    )

    private val log = LoggerFactory.getLogger(ADConfig::class.java)

    fun getBySource(configFile: String): Config = loadConfig(configFile)

    fun getByClasspath(): Config =
            loadConfig(ClassLoader.getSystemResource("adconfig.yaml")?.path ?: "")

    private fun loadConfig(configFile: String): Config {

        val emptyConfig = Config(
                "", 0, 3000,
                "", "",
                "", "", "",
                12, 12)

        val mapper = ObjectMapper(YAMLFactory())
        mapper.registerModule(KotlinModule()) // Enable Kotlin and data class support

        return try {
            Files.newBufferedReader(Paths.get(configFile))
                    .use { mapper.readValue(it, Config::class.java) }
                    .also {
                        log.info("$configFile read")
                    }
        }
        catch (e: java.io.IOException) {
            log.error("Authentication and authorization will fail - ${e.message}")
            emptyConfig
        }
        catch (e: SecurityException) {
            log.error("Authentication and authorization will fail - ${e.message}")
            emptyConfig
        }
    }


}