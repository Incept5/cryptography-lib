package org.incept5.cryptography.quarkus.config

import io.smallrye.config.ConfigMapping
import io.smallrye.config.WithName

@ConfigMapping(prefix = "incept5.cryptography.encryption")
interface EncryptionConfig {

    @get:WithName("key")
    val encryptionKey: EncryptionKey

    @get:WithName("decryption-keys")
    val decryptionKeys: List<EncryptionKey>

    interface EncryptionKey {
        @get:WithName("id")
        val id: String

        @get:WithName("aes")
        val aes: String

        @get:WithName("hmac")
        val hmac: String
    }
}
