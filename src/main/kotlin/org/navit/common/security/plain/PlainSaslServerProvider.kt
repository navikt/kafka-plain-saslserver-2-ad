package org.navit.common.security.plain

import java.security.Security
import java.security.Provider

class PlainSaslServerProvider protected constructor() : Provider(
        "NAV IT",
        1.0,
        "SASL/PLAIN Server Provider using binding verification against Active Directory") {

    init {
        put("SaslServerFactory." + PlainSaslServer.PLAIN_MECHANISM, PlainSaslServer.PlainSaslServerFactory::class.java.name)
    }

    companion object {

        private val serialVersionUID = 1L

        fun initialize() {
            Security.addProvider(PlainSaslServerProvider())
        }
    }
}