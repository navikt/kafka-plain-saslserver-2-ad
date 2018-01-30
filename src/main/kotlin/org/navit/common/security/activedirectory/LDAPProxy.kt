package org.navit.common.security.activedirectory

import com.unboundid.ldap.sdk.*
import org.slf4j.LoggerFactory
import org.yaml.snakeyaml.Yaml
import java.io.*

class LDAPProxy private constructor(
        val host: String,
        val port: Int,
        val baseDN: String,
        val filter: String,
        val uid: String,
        val grpBaseDN: String,
        val grpFilter: String,
        val grpUid: String) {

    private val ldapConnection = LDAPConnection()

    init {
        try {
            ldapConnection.connect(host, port)
            log.info("Successfully connected to LDAP($host,$port)")
        }
        catch (e: LDAPException) {
            log.error("Exception when connecting to LDAP($host,$port)")
            ldapConnection.setDisconnectInfo(DisconnectType.IO_ERROR,"Exception when connecting to LDAP($host,$port)", e)
        }
    }

    fun verifyUserAndPassword(user: String, pwd: String): ResultCode {

        return  try {
            //Search for user DN
            //val userDN = getUserDN(user)
            val userDN = "$uid=$user,"+baseDN

            log.info("user DN is $userDN")

            //do the simple bind with userDN and given password
            if (!userDN.isEmpty()) {
                log.info("Binding verification of $userDN and $pwd")
                ldapConnection.bind(userDN, pwd).resultCode
            }
            else {
                log.info("Could not find user DN for $user")
                ResultCode.INAPPROPRIATE_MATCHING
            }
        }
        catch (e: LDAPSearchException) {
            e.searchResult.resultCode
        }
        catch(e: LDAPException) {
            e.resultCode
        }
    }

    fun isUserMemberOf(user: String, group: String): Boolean {

        return try {
            //Search for user DN
            val userDN = getUserDN(user)
            val groupDN = getGroupDN(group)

            ldapConnection.compare(CompareRequest(groupDN,"uniqueMember",userDN)).compareMatched()
        }
        catch(e: LDAPException) {
            false
        }
    }

    private fun getUserDN( user: String): String {

        //eventually narrow down the provided filter with AND uid = <user>
        val filter = if (!filter.isEmpty()) {
            Filter.createANDFilter(
                    Filter.createEqualityFilter(uid, user),
                    Filter.create(filter)
            )}
        else {
            Filter.createEqualityFilter(uid, user)
        }

        val sResult = ldapConnection.search(SearchRequest(baseDN, SearchScope.SUB, filter, SearchRequest.NO_ATTRIBUTES))

        return if (sResult.resultCode == ResultCode.SUCCESS && sResult.entryCount == 1)
            sResult.searchEntries[0].dn
        else
            ""
    }

    private fun getGroupDN(group: String): String {

        //eventually narrow down the provided filter with AND groupUID = <group>
        val filter = if (!grpFilter.isEmpty()) {
            Filter.createANDFilter(
                    Filter.createEqualityFilter(grpUid, group),
                    Filter.create(grpFilter)
            )}
        else {
            Filter.createEqualityFilter(grpUid, group)
        }

        val sResult = ldapConnection.search(SearchRequest(grpBaseDN, SearchScope.SUB, filter, SearchRequest.NO_ATTRIBUTES))

        return if (sResult.resultCode == ResultCode.SUCCESS && sResult.entryCount == 1)
            sResult.searchEntries[0].dn
        else
            ""
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
                        adConfig["baseDN"]?.toString() ?: "",
                        adConfig["filter"]?.toString() ?: "",
                        adConfig["uid"]?.toString() ?: "uid",
                        adConfig["grpBaseDN"]?.toString() ?: "",
                        adConfig["grpFilter"]?.toString() ?: "",
                        adConfig["grpUid"]?.toString() ?: "cn"
                )
            }
            else { //defaulting to connection error in case of no config YAML
                LDAPProxy("",0,"","", "","","","")

            }
        }
    }
}