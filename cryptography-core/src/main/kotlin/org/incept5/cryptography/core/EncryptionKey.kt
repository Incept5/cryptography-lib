package org.incept5.cryptography.core

import javax.crypto.spec.SecretKeySpec

data class EncryptionKey(
    val keyId: String,
    val aesKey: SecretKeySpec,
    val hmacKey: SecretKeySpec,
) {
    override fun hashCode(): Int {
        return keyId.hashCode()
    }
}