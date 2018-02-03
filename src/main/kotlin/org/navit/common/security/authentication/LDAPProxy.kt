package org.navit.common.security.authentication

import com.unboundid.ldap.sdk.*
import org.slf4j.LoggerFactory
import org.yaml.snakeyaml.Yaml
import java.io.*

// Added
class LDAPProxy private constructor(
        val host: String,
        val port: Int,
        private val usrBaseDN: String,
        private val usrUid: String,
        private val grpBaseDN: String,
        private val grpUid: String,
        private val grpAttrName: String,
        bindDN: String,
        bindPwd: String) {

    private val ldapConnection = LDAPConnection()

    init {
        try {
            ldapConnection.connect(host, port)
            log.info("$ldapAuthentication successfully connected to ($host,$port)")
        }
        catch (e: LDAPException) {
            log.error("$ldapAuthentication authentication will fail! Exception when connecting to ($host,$port)")
            ldapConnection.setDisconnectInfo(DisconnectType.IO_ERROR,"Exception when connecting to LDAP($host,$port)", e)
        }

        try {
            //must perform binding for function isUserMemberOfAny
            ldapConnection.bind(bindDN,bindPwd)
            log.info("$ldapAuthentication successfully bind to ($host,$port) with $bindDN")
        }
        catch (e: LDAPException) {
            log.error("$ldapAuthentication authorization will fail! Exception when bind to ($host,$port) - ${e.diagnosticMessage}")
        }
    }

    fun canUserAuthenticate(user: String, pwd: String): Boolean {

        return  try {
            val userDN = "$usrUid=$user,$usrBaseDN"

            log.info("$ldapAuthentication trying bind for $userDN and given password")
            ldapConnection.bind(userDN, pwd).resultCode == ResultCode.SUCCESS

        }
        catch(e: LDAPException) {
            log.error("$ldapAuthentication bind exception, ${e.exceptionMessage}")
            false
        }
    }

    fun isUserMemberOfAny(user: String, groups: List<String>): Boolean {

            var result = false
            val userDN = "$usrUid=$user,$usrBaseDN"

            groups.forEach {

                val groupDN = "$grpUid=$it,$grpBaseDN"

                log.info("$ldapAuthentication trying compare-matched for $groupDN - $grpAttrName - $userDN")
                result = result || try {
                    ldapConnection.compare(CompareRequest(groupDN, grpAttrName, userDN)).compareMatched()
                }
                catch(e: LDAPException) {
                    log.error("$ldapAuthentication compare-matched exception - invalid group!, ${e.exceptionMessage}")
                    false
                }
            }

            return result
    }

    companion object {

        private val log = LoggerFactory.getLogger(LDAPProxy::class.java)
        private const val ldapAuthentication = "LDAP authentication:"

        fun init(configFile: String) : LDAPProxy {

            return if (!configFile.isEmpty()) {

                val adConfig = try {
                    Yaml().load<Map<String, *>>(FileInputStream(File(configFile)))
                } catch (e: FileNotFoundException) {
                    emptyMap<String, String>()
                }

                LDAPProxy(
                        adConfig["host"].toString(),
                        adConfig["port"]?.toString()?.toInt() ?: 0,
                        adConfig["usrBaseDN"].toString(),
                        adConfig["usrUid"].toString(),
                        adConfig["grpBaseDN"].toString(),
                        adConfig["grpUid"].toString(),
                        adConfig["grpAttrName"].toString(),
                        adConfig["bindDN"].toString(),
                        adConfig["bindPwd"].toString()
                )
            }
            else { //defaulting to connection error in case of no config YAML
                LDAPProxy("",0,"","","","","","","")
            }
        }
    }
}