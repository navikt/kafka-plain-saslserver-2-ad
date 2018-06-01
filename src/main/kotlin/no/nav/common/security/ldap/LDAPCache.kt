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

    private data class Bind(val name: String, val other: String)

    private class BindCacheLoader : CacheLoader<Bind, Bind> {
        override fun load(key: Bind): Bind = key
    }

    private data class Group(val name: String, val other: String)

    private class GroupCacheLoader : CacheLoader<Group, Group> {
        override fun load(key: Group): Group = key
    }

    private val bindCache: LoadingCache<Bind, Bind>
    private val groupCache: LoadingCache<Group, Group>

    private val log = LoggerFactory.getLogger(LDAPCache::class.java)

    init {

        val config = LDAPConfig.getByClasspath()

        bindCache = Caffeine.newBuilder()
                .maximumSize(1_000)
                .expireAfterWrite(config.usrCacheExpire.toLong(), TimeUnit.MINUTES)
                .build(BindCacheLoader())

        groupCache = Caffeine.newBuilder()
                .maximumSize(10_000)
                .expireAfterWrite(config.grpCacheExpire.toLong(), TimeUnit.MINUTES)
                .build(GroupCacheLoader())

        log.info("Bind and group caches are initialized")
    }

    fun userExists(userDN: String, pwd: String): Boolean =
        when (bindCache.getIfPresent(Bind(userDN, pwd))) {
            is Bind -> true
            else -> false
        }

    fun userAdd(userDN: String, pwd: String) {
        try {
            bindCache.get(Bind(userDN, pwd))
        } catch (e: java.util.concurrent.ExecutionException) {
            log.error("Exception in userAdd - ${e.cause}")
        }
    }

    fun groupAndUserExists(groupDN: String, userDN: String): Boolean =
        when (groupCache.getIfPresent(Group(groupDN, userDN))) {
            is Group -> true
            else -> false
        }

    fun groupAndUserAdd(groupDN: String, userDN: String) {
        try {
            groupCache.get(Group(groupDN, userDN))
        } catch (e: java.util.concurrent.ExecutionException) {
            log.error("Exception in groupAndUserAdd - ${e.cause}")
        }
    }

    // for test purpose

    fun invalidateAllBinds() = bindCache.invalidateAll().also { log.info("Bind cache reset") }

    fun invalidateAllGroups() = groupCache.invalidateAll().also { log.info("Group cachet reset") }
}