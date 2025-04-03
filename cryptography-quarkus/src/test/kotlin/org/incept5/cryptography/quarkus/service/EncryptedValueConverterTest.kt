package org.incept5.cryptography.quarkus.service

import org.incept5.cryptography.quarkus.service.EncryptedValueConverter
import org.incept5.cryptography.quarkus.service.StandardEncryptionService
import org.apache.commons.lang3.RandomStringUtils
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.InjectMocks
import org.mockito.Mock
import org.mockito.MockitoAnnotations
import org.mockito.kotlin.verify
import org.mockito.kotlin.verifyNoInteractions
import org.mockito.kotlin.whenever

class EncryptedValueConverterTest {

    @Mock
    lateinit var encryptionService: StandardEncryptionService

    @InjectMocks
    lateinit var encryptedValueConverter: EncryptedValueConverter

    companion object {
        const val CIPHER_TEXT = """
            {"provider":"Incdept5EncryptionProviderV1","keyId":"8d56336b-d2e0-4d2d-81f6-9ced981a62bd","hmac":"LfTPiM1m2e4SXjn9mIv9PVCXrVw1SfjMwkS7f+4TvWM=","encryptedValue":"8SBsHQBEDWGT4s1BRMhUe/CQO8Z251Azc/mbeiXKPYQ=","initialisationVector":"RCdfvoC671KIACenCDZujw=="}
        """
    }

    @BeforeEach
    fun setUp() {
        MockitoAnnotations.openMocks(this)
    }

    @Test
    fun `convert to database column success`() {
        // Given a text to convert
        val inputText = RandomStringUtils.randomAlphanumeric(10)
        whenever(encryptionService.encrypt(inputText)).thenReturn(CIPHER_TEXT)

        // When convert to db values
        val result = encryptedValueConverter.convertToDatabaseColumn(inputText)

        // Then the text is converted
        verify(encryptionService).encrypt(inputText)
        assertEquals(CIPHER_TEXT, result)
    }

    @Test
    fun `convert to database column success - encrypt null values`() {
        // Given a text to convert
        val inputText = null as String?
        whenever(encryptionService.encrypt(inputText)).thenReturn(CIPHER_TEXT)

        // When convert to db values
        val result = encryptedValueConverter.convertToDatabaseColumn(inputText)

        // Then the text is converted
        verify(encryptionService).encrypt(inputText)
        assertEquals(CIPHER_TEXT, result)
    }

    @Test
    fun `convert from database column success - decrypt cipher`() {
        // Given a text to convert
        val inputText = CIPHER_TEXT
        whenever(encryptionService.decrypt(inputText)).thenReturn(CIPHER_TEXT)

        // When convert from db values
        encryptedValueConverter.convertToEntityAttribute(inputText)

        // Then the text is converted
        verify(encryptionService).decrypt(inputText)
    }

    @Test
    fun `convert from database column success - null values`() {
        // Given a text to convert
        val inputText = null

        // When convert from db values
        val result = encryptedValueConverter.convertToEntityAttribute(inputText)

        // Then the text is converted
        verifyNoInteractions(encryptionService)
        assertNull(result)
    }

    @Test
    fun `convert from database column success - plain text is bypassed`() {
        // Given a text to convert
        val inputText = RandomStringUtils.randomAlphanumeric(10)

        // When convert from db values
        val result = encryptedValueConverter.convertToEntityAttribute(inputText)

        // Then the text is converted
        verifyNoInteractions(encryptionService)
        assertEquals(inputText, result)
    }

}
