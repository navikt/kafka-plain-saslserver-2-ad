package org.navit.common.security.authentication

import com.google.common.cache.CacheBuilder
import com.google.common.cache.LoadingCache
import com.google.common.cache.CacheLoader
import org.slf4j.LoggerFactory
import java.util.concurrent.TimeUnit

object LDAPCache {

    data class Binded(val name: String, val other: String)

    class BindedCacheLoader : CacheLoader<Binded, Binded>() {

        override fun load(key: Binded): Binded {
            return key
        }
    }

    data class Grouped(val name: String, val other: String)

    class GroupedCacheLoader : CacheLoader<Grouped,Grouped>() {

        override fun load(key: Grouped): Grouped {
            return key
        }
    }

    private val bindedCache: LoadingCache<Binded, Binded>
    private val groupedCache: LoadingCache<Grouped,Grouped>

    private const val ldapCache = "LDAP cache:"
    private val log = LoggerFactory.getLogger(LDAPCache::class.java)

    init {
        bindedCache = CacheBuilder.newBuilder()
                .maximumSize(10000)
                .expireAfterWrite(2,TimeUnit.MINUTES)
                .build(BindedCacheLoader())

        groupedCache = CacheBuilder.newBuilder()
                .maximumSize(1000)
                .expireAfterWrite(4,TimeUnit.MINUTES)
                .build(GroupedCacheLoader())

        log.info("$ldapCache is initialized")

    }

    fun alreadyBinded(userDN: String, pwd: String): Boolean =
         when(bindedCache.getIfPresent(Binded(userDN,pwd))) {
            is Binded -> true
            else -> false
        }

    fun getBinded(userDN: String, pwd: String) {

        try {
            bindedCache.get(Binded(userDN,pwd))
        }
        catch (e: java.util.concurrent.ExecutionException) {
            log.error("$ldapCache exception in getBinded - ${e.cause}")
        }
        catch (e: com.google.common.util.concurrent.ExecutionError) {
            log.error("$ldapCache exception in getBinded - ${e.cause}")
        }
    }

    fun alreadyGrouped(groupDN: String, userDN: String) : Boolean =
            when(groupedCache.getIfPresent(Grouped(groupDN,userDN))) {
                is Grouped -> true
                else -> false
            }

    fun getGrouped(groupDN: String, userDN: String) {

        try {
            groupedCache.get(Grouped(groupDN,userDN))
        }
        catch (e: java.util.concurrent.ExecutionException) {
            log.error("$ldapCache exception in getGrouped - ${e.cause}")
        }
        catch (e: com.google.common.util.concurrent.ExecutionError) {
            log.error("$ldapCache exception in getGrouped - ${e.cause}")
        }
    }



}