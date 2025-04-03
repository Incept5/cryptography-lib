package org.incept5.cryptography.core

/**
 * Core Encryption Service allows clients to encrypt and decrypt data
 * without worrying about the implementation details.
 */
interface EncryptionService {

    fun encrypt(plainBytes: ByteArray?): String

    fun encrypt(plainText: String?): String {
        return encrypt(plainText?.toByteArray())
    }

    fun decrypt(cipherText: String): String? {
        val bytes = decryptAsBytes(cipherText)
        return if (bytes != null) String(bytes) else null
    }

    fun decryptAsBytes(cipherText: String): ByteArray?

}