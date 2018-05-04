package no.nav.common.security.ldap

import com.github.benmanes.caffeine.cache.CacheLoader
import com.github.benmanes.caffeine.cache.Caffeine
import com.github.benmanes.caffeine.cache.LoadingCache
import org.slf4j.LoggerFactory
import java.util.concurrent.TimeUnit

/**
 * A class using caffeine cache for 2 purposes
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

    private class BoundedCacheLoader : CacheLoader<Bounded, Bounded> {

        override fun load(key: Bounded): Bounded {
            return key
        }
    }

    private data class Grouped(val name: String, val other: String)

    private class GroupedCacheLoader : CacheLoader<Grouped, Grouped> {

        override fun load(key: Grouped): Grouped {
            return key
        }
    }

    private val boundedCache: LoadingCache<Bounded, Bounded>
    private val groupedCache: LoadingCache<Grouped, Grouped>

    private val log = LoggerFactory.getLogger(LDAPCache::class.java)

    init {

        val config = LDAPConfig.getByClasspath()

        boundedCache = Caffeine.newBuilder()
                .maximumSize(1_000)
                .expireAfterWrite(config.usrCacheExpire.toLong(),TimeUnit.MINUTES)
                .build(BoundedCacheLoader())

        groupedCache = Caffeine.newBuilder()
                .maximumSize(10_000)
                .expireAfterWrite(config.grpCacheExpire.toLong(),TimeUnit.MINUTES)
                .build(GroupedCacheLoader())

        log.info("Bind and group caches are initialized")
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
    }

    // for test purpose

    fun invalidateAllBounded() = boundedCache.invalidateAll().also { log.info("Group cache reset") }

    fun invalidateAllGroups() = groupedCache.invalidateAll().also { log.info("Bind cachet reset") }
}