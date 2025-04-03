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

        return if (!cipherText.contains("VeloEncryptionProviderV1")) {
            cipherText
        } else {
            encryptionService.decrypt(cipherText)
        }
    }
}
