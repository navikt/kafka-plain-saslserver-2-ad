package no.nav.common.security.ldap

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory
import com.fasterxml.jackson.module.kotlin.KotlinModule
import org.slf4j.LoggerFactory
import java.lang.IllegalArgumentException
import java.net.URL
import java.nio.file.FileSystemNotFoundException
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

object LDAPConfig {

    data class Config(
        val host: String,
        val port: Int,
        val connTimeout: Int,
        val usrBaseDN: String,
        val usrUid: String,
        val grpBaseDN: String,
        val grpUid: String,
        val grpAttrName: String,
        val usrCacheExpire: Int,
        val grpCacheExpire: Int
    )

    private val log = LoggerFactory.getLogger(LDAPConfig::class.java)
    private val cache: Config

    init {
        cache = loadConfig(ClassLoader.getSystemResource("ldapconfig.yaml")
                ?: URL(""))
        log.info("LDAPConfig for classpath is cached")
    }

    fun getBySource(configFile: String): Config {
        val prefix = if (System.getProperty("os.name").startsWith("Windows")) "file:/" else "file:"
        return loadConfig(URL(prefix + System.getProperty("user.dir") + "/" + configFile))
    }

    fun getByClasspath(): Config = cache

    private fun loadConfig(configFile: URL): Config {

        val mapper = ObjectMapper(YAMLFactory())

        mapper.registerModule(KotlinModule()) // Enable Kotlin and data class support

        val errMsg = "Authentication and authorization will fail - "
        val defaultDir = Paths.get("").toAbsolutePath()
        val filePath = try {
            Paths.get(configFile.toURI())
        } catch (e: IllegalArgumentException) {
            log.error(errMsg + e.message)
            defaultDir
        } catch (e: FileSystemNotFoundException) {
            log.error(errMsg + e.message)
            defaultDir
        } catch (e: SecurityException) {
            log.error(errMsg + e.message)
            defaultDir
        }

        val emptyConfig = Config(
                "", 0, 3000,
                "", "",
                "", "", "",
                2, 4)

        if (filePath == defaultDir) return emptyConfig

        return try {
            Files.newBufferedReader(filePath)
                    .use {
                        mapper.readValue(it, Config::class.java)
                    }
                    .also {
                        log.info("$configFile read")
                    }
        } catch (e: java.io.IOException) {
            log.error(errMsg + e.message)
            emptyConfig
        } catch (e: SecurityException) {
            log.error(errMsg + e.message)
            emptyConfig
        }
    }
}

// A couple of extension functions for Config
fun LDAPConfig.Config.toUserDN(user: String) = "$usrUid=$user,$usrBaseDN"
fun LDAPConfig.Config.toUserDNBasta(user: String) = "$usrUid=$user,ou=ApplAccounts,$usrBaseDN"
