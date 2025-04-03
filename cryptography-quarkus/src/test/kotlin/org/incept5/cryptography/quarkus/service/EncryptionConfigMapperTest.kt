package org.incept5.cryptography.quarkus.service

import org.incept5.cryptography.quarkus.config.EncryptionConfig
import org.incept5.cryptography.quarkus.config.EncryptionConfigMapper
import org.apache.commons.codec.binary.Base64
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import javax.crypto.spec.SecretKeySpec

class EncryptionConfigMapperTest {

    class MockEncryptionKey : EncryptionConfig.EncryptionKey {
        override val id: String
            get() = "81b4f837-c134-4e7f-bb5e-802d5dcc5d4c"
        override val aes: String
            get() = "8hV/a1MfXxjS54JS+35TMQx7K2TH/8eX6BtrwRKXARg="
        override val hmac: String
            get() = "sHjLLmW3wA6KWu3cBDJwi9bsVD7bqoTVEzJHacgSfns="

    }

    @Test
    fun `convert encryption config to domain entity`() {
        // Given an encryption key from config
        val encryptionKey = MockEncryptionKey()

        // When convert to domain
        val encryptionConfigMapper = EncryptionConfigMapper()
        val result = encryptionConfigMapper.convertToDomain(encryptionKey)

        // Then the conversion is success
        val expectedAes = SecretKeySpec(Base64.decodeBase64(encryptionKey.aes), "AES")
        val expectedHmac = SecretKeySpec(Base64.decodeBase64(encryptionKey.hmac), "HmacSHA256")
        assertEquals(encryptionKey.id, result.keyId)
        assertEquals(expectedAes, result.aesKey)
        assertEquals(expectedHmac, result.hmacKey)
    }
}
