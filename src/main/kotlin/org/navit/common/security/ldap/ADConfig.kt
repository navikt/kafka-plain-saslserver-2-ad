package org.navit.common.security.ldap

import org.slf4j.LoggerFactory
import org.yaml.snakeyaml.Yaml
import java.io.File
import java.io.FileInputStream
import java.io.FileNotFoundException

object ADConfig {

    private val log = LoggerFactory.getLogger(ADConfig::class.java)

    fun getBySource(configFile: String): Map<String, Any?> = readConfig(configFile)

    fun getByClasspath(): Map<String, Any?> =
        readConfig(ClassLoader.getSystemResource("adconfig.yaml")?.path ?: "")

    private fun str2Int(str: String?, default: Int) =
            try { str?.toInt() ?: default }
            catch (e: NumberFormatException) { default }

    private fun readConfig(configFile: String): Map<String, Any?> {

        val co =  when(configFile.isEmpty()) {
            true -> emptyMap()
            else -> {
                try {
                    Yaml().load<Map<String, *>>(FileInputStream(File(configFile))).let {
                        it.map { Pair(it.key,it. value?.toString() ?: "") }.toMap().also {
                            log.info("$configFile read")
                        }
                    }
                } catch (e: FileNotFoundException) {
                    log.error("Authentication and authorization will fail, no $configFile found!")
                    emptyMap<String, String>()
                }
            }
        }

        return when (co.isEmpty()) {
            true -> mapOf<String, Any?>(
                    "host" to "", "port" to 0, "connTimeout" to 3000,
                    "usrBaseDN" to "", "usrUid" to "",
                    "grpBaseDN" to "", "grpUid" to "", "grpAttrName" to "",
                    "usrCacheExpire" to 12, "grpCacheExpire" to 12)
            else -> mapOf<String, Any?>(
                    "host" to co["host"].toString(),
                    "port" to str2Int(co["port"],0),
                    "connTimeout" to str2Int(co["connTimeout"],3000),
                    "usrBaseDN" to co["usrBaseDN"].toString(),
                    "usrUid" to co["usrUid"].toString(),
                    "grpBaseDN" to co["grpBaseDN"].toString(),
                    "grpUid" to co["grpUid"].toString(),
                    "grpAttrName" to co["grpAttrName"].toString(),
                    "usrCacheExpire" to str2Int(co["usrCacheExpire"],12),
                    "grpCacheExpire" to str2Int(co["grpCacheExpire"],12))
        }
    }


}