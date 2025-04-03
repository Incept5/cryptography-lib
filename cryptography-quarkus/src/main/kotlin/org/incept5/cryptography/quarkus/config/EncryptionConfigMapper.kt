package org.incept5.cryptography.quarkus.config

import jakarta.enterprise.context.ApplicationScoped
import org.apache.commons.codec.binary.Base64.decodeBase64
import org.incept5.cryptography.core.EncryptionKey
import javax.crypto.spec.SecretKeySpec

@ApplicationScoped
class EncryptionConfigMapper {
    companion object {
        @JvmStatic
        fun mapStringToAesSecretKeySpec(aesStr: String): SecretKeySpec {
            val passPhrase: ByteArray = decodeBase64(aesStr)
            return SecretKeySpec(passPhrase, "AES")
        }

        @JvmStatic
        fun mapStringToHmacSecretKeySpec(hmacStr: String): SecretKeySpec {
            val passPhrase: ByteArray = decodeBase64(hmacStr)
            return SecretKeySpec(passPhrase, "HmacSHA256")
        }
    }

    fun convertToDomain(sourceKey: EncryptionConfig.EncryptionKey): EncryptionKey {
        return EncryptionKey(
            sourceKey.id,
            mapStringToAesSecretKeySpec(sourceKey.aes),
            mapStringToHmacSecretKeySpec(sourceKey.hmac)
        )
    }

}
