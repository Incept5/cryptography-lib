package org.incept5.cryptography.vault

import java.util.UUID

/**
 * Vault allows clients to store and retrieve data
 * which is encrypted then encrypted at rest by the Vault.
 */
interface Vault {

    fun store(plainText: String?): UUID {
        return store(plainText?.toByteArray())
    }

    fun store(plainBytes: ByteArray?): UUID

    fun retrieveAsBytes(id: UUID): ByteArray?

    fun retrieve(id: UUID): String? {
        val bytes = retrieveAsBytes(id)
        return if (bytes != null) String(bytes) else null
    }


    fun delete(id: UUID)
}