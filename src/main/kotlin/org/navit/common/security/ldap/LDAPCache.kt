package org.navit.common.security.ldap

import com.google.common.cache.CacheBuilder
import com.google.common.cache.LoadingCache
import com.google.common.cache.CacheLoader
import org.slf4j.LoggerFactory
import java.util.concurrent.TimeUnit

/**
 * A class using google guava cache for 2 purposes
 * - caching of successful ldap bindings
 * - caching of confirmed group membership
 *
 * Each of them has limited lifetime for entries, in order to reflect surrounding reality,
 * change in authentication and group membership
 *
 * NO test cases for this simple class
 */

object LDAPCache {

    private data class Bounded(val name: String, val other: String)

    private class BoundedCacheLoader : CacheLoader<Bounded, Bounded>() {

        override fun load(key: Bounded): Bounded {
            return key
        }
    }

    private data class Grouped(val name: String, val other: String)

    private class GroupedCacheLoader : CacheLoader<Grouped, Grouped>() {

        override fun load(key: Grouped): Grouped {
            return key
        }
    }

    private val boundedCache: LoadingCache<Bounded, Bounded>
    private val groupedCache: LoadingCache<Grouped, Grouped>

    private val log = LoggerFactory.getLogger(LDAPCache::class.java)

    init {
        boundedCache = CacheBuilder.newBuilder()
                .maximumSize(1000)
                .expireAfterWrite(2,TimeUnit.MINUTES)
                .build(BoundedCacheLoader())

        groupedCache = CacheBuilder.newBuilder()
                .maximumSize(10000)
                .expireAfterWrite(4,TimeUnit.MINUTES)
                .build(GroupedCacheLoader())

        log.info("Caches are initialized")
    }

    fun alreadyBounded(userDN: String, pwd: String): Boolean =
         when(boundedCache.getIfPresent(Bounded(userDN, pwd))) {
            is Bounded -> true
            else -> false
        }

    fun getBounded(userDN: String, pwd: String) {

        try {
            boundedCache.get(Bounded(userDN, pwd))
        }
        catch (e: java.util.concurrent.ExecutionException) {
            log.error("Exception in getBounded - ${e.cause}")
        }
        catch (e: com.google.common.util.concurrent.ExecutionError) {
            log.error("Exception in getBounded - ${e.cause}")
        }
    }

    fun alreadyGrouped(groupDN: String, userDN: String) : Boolean =
            when(groupedCache.getIfPresent(Grouped(groupDN, userDN))) {
                is Grouped -> true
                else -> false
            }

    fun getGrouped(groupDN: String, userDN: String) {

        try {
            groupedCache.get(Grouped(groupDN, userDN))
        }
        catch (e: java.util.concurrent.ExecutionException) {
            log.error("Exception in getGrouped - ${e.cause}")
        }
        catch (e: com.google.common.util.concurrent.ExecutionError) {
            log.error("Exception in getGrouped - ${e.cause}")
        }
    }
}