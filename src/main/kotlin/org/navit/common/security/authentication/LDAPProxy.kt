package org.navit.common.security.authentication

import com.unboundid.ldap.sdk.*
import org.slf4j.LoggerFactory
import org.yaml.snakeyaml.Yaml
import java.io.*

// Added
class LDAPProxy private constructor(
        val host: String,
        val port: Int,
        val usrBaseDN: String,
        val usrUid: String,
        val grpBaseDN: String,
        val grpUid: String,
        val grpAttrName: String) {

    private val ldapConnection = LDAPConnection()

    init {
        try {
            ldapConnection.connect(host, port)
            log.info("Successfully connected to LDAP($host,$port)")
        }
        catch (e: LDAPException) {
            log.error("Authentication will fail! Exception when connecting to LDAP($host,$port)")
            ldapConnection.setDisconnectInfo(DisconnectType.IO_ERROR,"Exception when connecting to LDAP($host,$port)", e)
        }
    }

    fun canUserAuthenticate(user: String, pwd: String): Boolean {

        return  try {
            val userDN = "$usrUid=$user,$usrBaseDN"

            log.info("DN for $user is $userDN")

            log.info("Trying LDAP bind of $userDN and given password")
            ldapConnection.bind(userDN, pwd).resultCode == ResultCode.SUCCESS

        }
        catch(e: LDAPException) {
            log.error("LDAP bind exception, ${e.exceptionMessage}")
            false
        }
    }

    fun isUserMemberOf(user: String, group: String): Boolean {

        return try {
            val userDN = "$usrUid=$user,$usrBaseDN"
            val groupDN = "$grpUid=$group,$grpBaseDN"

            log.info("Trying LDAP compare matched for $groupDN - $grpAttrName - $userDN")
            ldapConnection.compare(CompareRequest(groupDN,grpAttrName,userDN)).compareMatched()
        }
        catch(e: LDAPException) {
            log.error("LDAP compare exception, ${e.exceptionMessage}")
            false
        }
    }

    companion object {

        private val log = LoggerFactory.getLogger(LDAPProxy::class.java)

        fun init(configFile: String) : LDAPProxy {

            return if (!configFile.isEmpty()) {

                val adConfig = try {
                    Yaml().load<Map<String, *>>(FileInputStream(File(configFile)))
                } catch (e: FileNotFoundException) {
                    emptyMap<String, String>()
                }

                LDAPProxy(
                        adConfig["host"]?.toString() ?: "",
                        adConfig["port"]?.toString()?.toInt() ?: 0,
                        adConfig["usrBaseDN"]?.toString() ?: "",
                        adConfig["usrUid"]?.toString() ?: "",
                        adConfig["grpBaseDN"]?.toString() ?: "",
                        adConfig["grpUid"]?.toString() ?: "",
                        adConfig["grpAttrName"]?.toString() ?: ""
                )
            }
            else { //defaulting to connection error in case of no config YAML
                LDAPProxy("",0,"","","","","")
            }
        }
    }
}