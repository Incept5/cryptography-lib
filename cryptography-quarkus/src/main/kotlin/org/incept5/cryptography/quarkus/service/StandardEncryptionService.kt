package org.incept5.cryptography.quarkus.service

import org.incept5.cryptography.core.EncryptionService
import org.incept5.cryptography.quarkus.config.EncryptionConfig
import org.incept5.cryptography.quarkus.config.EncryptionConfigMapper
import jakarta.inject.Singleton
import org.incept5.cryptography.core.EncryptedValue
import org.incept5.cryptography.provider.EncryptionProvider
import org.incept5.cryptography.provider.EncryptionProviderImpl

@Singleton
class StandardEncryptionService(
    encryptionConfig: EncryptionConfig,
    encryptionConfigMapper: EncryptionConfigMapper
) : EncryptionService {

    private val encryptionProvider: EncryptionProvider

    init {
        val encryptionKey = encryptionConfigMapper.convertToDomain(encryptionConfig.encryptionKey)
        val decryptionKeys = encryptionConfig.decryptionKeys.map { encryptionConfigMapper.convertToDomain(it) }
        encryptionProvider = EncryptionProviderImpl(encryptionKey, decryptionKeys)
    }

    override fun encrypt(plainBytes: ByteArray?): String {
        return encryptionProvider.encrypt(plainBytes).asString()
    }

    override fun decryptAsBytes(cipherText: String): ByteArray? {
        return encryptionProvider.decryptAsBytes(EncryptedValue.fromString(cipherText))
    }

}
