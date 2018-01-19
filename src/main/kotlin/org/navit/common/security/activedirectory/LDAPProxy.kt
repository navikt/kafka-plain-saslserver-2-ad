package org.navit.common.security.activedirectory

import com.unboundid.ldap.sdk.*
import org.yaml.snakeyaml.Yaml
import java.io.*

class LDAPProxy private constructor(
        val host: String,
        val port: Int,
        val baseDN: String,
        val filter: String) {

    fun verifyUserAndPassword(user: String = "", pwd: String = ""): ResultCode {

        var result: ResultCode
        val ldapConnection = LDAPConnection()

        try {
            ldapConnection.connect(host, port)

            //eventually narrow down the provided filter with AND uid = <user>
            val filter = if (!filter.isEmpty()) {
                Filter.createANDFilter(
                    Filter.createEqualityFilter("uid",user),
                    Filter.create(filter)
            )}
            else {
                Filter.createEqualityFilter("uid",user)
            }

            val sResult = ldapConnection.search(SearchRequest(baseDN, SearchScope.SUB, filter, SearchRequest.NO_ATTRIBUTES))

            //do the simple bind with found dn
            result = if (sResult.resultCode == ResultCode.SUCCESS && sResult.entryCount == 1)
                ldapConnection.bind(sResult.searchEntries[0].dn, pwd).resultCode
            else
                ResultCode.INAPPROPRIATE_MATCHING

            ldapConnection.close()
        }
        catch(e: LDAPException) {
            result = e.resultCode
        }
        finally {
            ldapConnection.close()
        }

        return result
    }

    companion object {

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
                    adConfig["filter"]?.toString() ?: ""
                )
            }
            else { //defaulting to connection error
                LDAPProxy(
                    "",
                    0,
                    "dc=example,dc=com",
                    "(&(objectClass=person)(objectClass=inetOrgPerson))"
                )

            }
        }
    }
}
