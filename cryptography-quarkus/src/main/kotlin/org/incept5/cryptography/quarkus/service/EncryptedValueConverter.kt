package org.incept5.cryptography.quarkus.service

import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject
import jakarta.persistence.AttributeConverter
import jakarta.persistence.Converter

@Converter
@ApplicationScoped
class EncryptedValueConverter : AttributeConverter<String, String> {

    @Inject
    lateinit var encryptionService: StandardEncryptionService
    override fun convertToDatabaseColumn(plainText: String?): String {
        return encryptionService.encrypt(plainText)
    }

    override fun convertToEntityAttribute(cipherText: String?): String? {
        if (cipherText == null) return null

        return if (!cipherText.contains("Incept5EncryptionProviderV1")) {
            cipherText
        } else {
            val bytes = encryptionService.decryptAsBytes(cipherText)
            if (bytes != null) String(bytes) else null
        }
    }
}
