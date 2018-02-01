package org.navit.common.security.plain

import java.security.Security
import java.security.Provider

class PlainSaslServerProvider private constructor() : Provider(
        "NAV IT",
        1.0,
        "SASL/PLAIN Server Provider using LDAP binding verification") {

    init {
        put("SaslServerFactory." + PlainSaslServer.PLAIN_MECHANISM, PlainSaslServer.PlainSaslServerFactory::class.java.name)
    }

    companion object {

        private const val serialVersionUID = 1L

        fun initialize() {
            Security.addProvider(PlainSaslServerProvider())
        }
    }
}