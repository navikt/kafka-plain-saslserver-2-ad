package org.navit.common.security.authorization

import kafka.security.auth.Acl
import kafka.security.auth.Operation
import kafka.security.auth.PermissionType
import org.amshove.kluent.`should be`
import org.apache.kafka.common.acl.AclOperation
import org.apache.kafka.common.security.auth.KafkaPrincipal
import org.jetbrains.spek.api.Spek
import org.jetbrains.spek.api.dsl.*
import org.navit.common.security.common.InMemoryLDAPServer
import org.navit.common.security.common.JAASContext


object GroupAuthorizerSpec : Spek({

    // create read allowance for ldap group
    fun cReadAS(ldapGroup: String) : Set<Acl> {
        return setOf(
                Acl(
                        KafkaPrincipal(KafkaPrincipal.USER_TYPE, ldapGroup),
                        PermissionType.fromString("Allow"),
                        "*",
                        Operation.fromJava(AclOperation.READ)
                )
        )
    }

    // create describe allowance for 2 ldap groups
    fun cDescribeAS(ldapGroup1: String, ldapGroup2: String) : Set<Acl> {
        return setOf(
                Acl(
                        KafkaPrincipal(KafkaPrincipal.USER_TYPE, ldapGroup1),
                        PermissionType.fromString("Allow"),
                        "*",
                        Operation.fromJava(AclOperation.DESCRIBE)
                ),
                Acl(
                        KafkaPrincipal(KafkaPrincipal.USER_TYPE, ldapGroup2),
                        PermissionType.fromString("Allow"),
                        "*",
                        Operation.fromJava(AclOperation.DESCRIBE)
                )
        )
    }

    // create write allowance for ldap group
    fun cWriteAS(ldapGroup: String) : Set<Acl> {
        return setOf(
                Acl(
                        KafkaPrincipal(KafkaPrincipal.USER_TYPE, ldapGroup),
                        PermissionType.fromString("Allow"),
                        "*",
                        Operation.fromJava(AclOperation.WRITE)
                )
        )
    }

    // helper function for creating KafkaPrincipal
    fun createKP (userName: String): KafkaPrincipal {
        return KafkaPrincipal(KafkaPrincipal.USER_TYPE,userName)
    }

    // set the JAAS config in order to do successful init of LDAPAuthorization
    JAASContext.setUp()

    describe("GroupAuthorizer class test specifications") {

        beforeGroup {
            InMemoryLDAPServer.start()
        }

        given("a acls with describe allowance - 2 ldap groups") {

            val aclDescribe = cDescribeAS("ktACons","ktAProd")

            on("a member user in group 1") {
                it("should retrn true") {
                    val authorizer = GroupAuthorizer()
                    val authorized = authorizer.authorize(createKP("cdoe"),aclDescribe)

                    authorized.`should be`(true)
                }
            }
            on("a member user in group 2") {
                it("should retrn true") {
                    val authorizer = GroupAuthorizer()
                    val authorized = authorizer.authorize(createKP("adoe"),aclDescribe)

                    authorized.`should be`(true)
                }
            }
            on("a non-member user in any group") {
                it("should retrn false") {
                    val authorizer = GroupAuthorizer()
                    val authorized = authorizer.authorize(createKP("ddoe"),aclDescribe)

                    authorized.`should be`(false)
                }
            }
        }

        given("a acls with read allowance ") {

            val aclRead = cReadAS("ktACons")

            on("a member user") {

                it("should return true") {

                    val authorizer = GroupAuthorizer()
                    val authorized = authorizer.authorize(createKP("bdoe"),aclRead)

                    authorized.`should be`(true)
                }
            }

            on("a non-member user") {

                it("should return false") {

                    val authorizer = GroupAuthorizer()
                    val authorized = authorizer.authorize(createKP("adoe"),aclRead)

                    authorized.`should be`(false)
                }
            }
        }

        given("a acls with write allowance ") {

            val aclWrite = cWriteAS("ktAProd")

            on("a non-member user") {

                it("should return false") {

                    val authorizer = GroupAuthorizer()
                    val authorized = authorizer.authorize(createKP("bdoe"),aclWrite)

                    authorized.`should be`(false)
                }
            }

            on("a member user") {

                it("should return true") {

                    val authorizer = GroupAuthorizer()
                    val authorized = authorizer.authorize(createKP("adoe"),aclWrite)

                    authorized.`should be`(true)
                }
            }
        }

        afterGroup {
            InMemoryLDAPServer.stop()
        }
    }
})